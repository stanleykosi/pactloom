//! Two disjoint native purposes for fresh enrollment and manifest receipts.
use super::pair::PairBinding;
use super::*;
use crate::signer_v3_pair_data::{SignerV3PairPresentationV1, SignerV3PairedV1};
use crate::signer_v3_receipt_data::*;
#[derive(Default)]
pub(super) struct ReceiptSlots {
    enrollment: EnrollmentSlot,
    manifest: ManifestSlot,
}

const ENROLLMENT_REVIEW: u8 = 132;
const ENROLLMENT_ADMITTED: u8 = 133;
const ENROLLMENT_DONE: u8 = 134;
#[derive(Default)]
struct EnrollmentSlot {
    binding: Option<Arc<EnrollmentBinding>>,
    wire: Option<SignerV3EnrollmentPresentationV1>,
    phase: u8,
    reported: bool,
}
struct EnrollmentBinding {
    pair: Arc<PairBinding>,
    p: SignerV3EnrollmentPresentationV1,
    deadline: Instant,
    last_wall: AtomicU64,
}
impl EnrollmentBinding {
    fn new(pair: Arc<PairBinding>, p: SignerV3EnrollmentPresentationV1) -> Result<Arc<Self>> {
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
            return Err(rejected("fresh receipt review expired"));
        }
        Ok(())
    }
    fn current(&self, phase: u8) -> Result<()> {
        self.bounds()?;
        self.pair.entry.core.check_action_restrictions()?;
        if self.pair.entry.core.phase.phase(self.pair.entry.slot()) != phase {
            return Err(rejected("fresh receipt purpose consumed"));
        }
        Ok(())
    }
}
pub struct SignerV3EnrollmentTicketV1 {
    binding: Arc<EnrollmentBinding>,
    consumed: bool,
}
impl SignerV3EnrollmentTicketV1 {
    pub fn presentation(&self) -> &SignerV3EnrollmentPresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(132)
    }
}
impl Drop for SignerV3EnrollmentTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3EnrollmentOutboundV1 {
    binding: Arc<EnrollmentBinding>,
    consumed: bool,
}
impl Drop for SignerV3EnrollmentOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3EnrollmentFinalV1 {
    effect: AtomicU8,
    binding: Arc<EnrollmentBinding>,
    consumed: bool,
}
impl SignerV3EnrollmentFinalV1 {
    pub fn presentation(&self) -> &SignerV3EnrollmentPresentationV1 {
        &self.binding.p
    }
    pub fn facts(&self) -> &SignerV3EnrollmentFactsV1 {
        &self.binding.p.facts
    }
    pub fn original_review_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.pair.entry.original_source
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(133)
    }
    /// Invoke only under actual validated source/SQL locks. Move the entire
    /// owned transaction into this closure: commit, rollback and destruction
    /// must finish before it returns. No await, enqueue, or escaping guard.
    pub fn execute_enrollment_publication(
        &self,
        publication: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.check_current()?;
        self.effect
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                self.binding.pair.entry.core.phase.revoke();
                rejected("fresh receipt publication is one-use")
            })?;
        let core = &self.binding.pair.entry.core;
        let mut attempt = ReceiptEffectAttempt {
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
    pub fn finish_review(mut self) -> Result<()> {
        let core = &self.binding.pair.entry.core;
        if self.effect.load(Ordering::Acquire) != 2
            || unsafe { libc::getpid() } != core.owner_pid
            || unsafe { libc::geteuid() } != core.owner_uid
            || core.phase.phase(self.binding.pair.entry.slot()) != 133
        {
            return Err(rejected(
                "fresh receipt finish lacks completed original publication",
            ));
        }
        core.phase
            .observe_v3_enrollment_published(self.binding.pair.entry.slot())?;
        self.consumed = true;
        Ok(())
    }
}
impl Drop for SignerV3EnrollmentFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
fn enrollment_matches(
    p: &SignerV3EnrollmentPresentationV1,
    entry: &SignerV3SourceEntryPresentationV1,
    pair: &SignerV3PairPresentationV1,
    result: &SignerV3PairedV1,
    prior: Option<&SignerV3EnrollmentPresentationV1>,
) -> bool {
    let f = &p.facts;
    p.actor == entry.actor
        && p.source_ceiling_ms == entry.source_ceiling_ms
        && p.review_ceiling_ms <= pair.channel_ceiling_ms
        && f.entry_presentation_digest == entry.presentation_digest
        && f.source_identity_digest == result.source_identity_digest
        && f.pair_grant_id == result.grant_id
        && f.pair_key_digest == result.key_digest
        && f.pair_channel_digest == result.channel_digest
        && f.pair_generation == result.generation
        && f.source_expires_at_ms == entry.facts.source_expires_at_ms
        && f.expires_at_ms <= pair.facts.channel_expires_at_ms
        && f.reviewed_at_ms >= pair.facts.reviewed_at_ms
        && (f.historical_enrollment_ref == entry.facts.original_enrollment_ref
            && f.historical_manifest_ref == entry.facts.original_manifest_ref)
}
impl SignerFinancialWorkflowOriginV1 {
    pub fn offer_v3_enrollment(
        &mut self,
        facts: SignerV3EnrollmentFactsV1,
        original_review: Instant,
    ) -> Result<SignerV3EnrollmentPresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        let s = &mut self.v3_entry;
        let pair = s
            .pair
            .binding
            .as_ref()
            .ok_or_else(|| rejected("fresh receipt before Pair"))?;
        pair.channel_bounds()?;
        let result = s
            .pair
            .result
            .as_ref()
            .ok_or_else(|| rejected("fresh receipt before possession proof"))?;
        if s.receipts.enrollment.binding.is_some()
            || original_review > pair.channel_deadline
            || original_review > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected("fresh receipt one exact window"));
        }
        let mut p = SignerV3EnrollmentPresentationV1 {
            actor: pair.p.actor.clone(),
            facts,
            notice: ENROLLMENT_NOTICE.into(),
            challenge: state::nonce()?,
            source_ceiling_ms: pair.p.source_ceiling_ms,
            review_ceiling_ms: self
                .clocks
                .restrictive_offset(original_review, pair.channel_deadline)?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        if !enrollment_matches(
            &p,
            &pair.entry.wire.presentation,
            &pair.p,
            result,
            s.receipts.enrollment.wire.as_ref(),
        ) {
            return Err(rejected("fresh receipt original record/Pair predecessor"));
        }
        let binding = EnrollmentBinding::new(Arc::clone(pair), p.clone())?;
        self.core.phase.step(self.target.index(), 131, 132)?;
        s.receipts.enrollment.binding = Some(binding);
        s.receipts.enrollment.wire = Some(p.clone());
        s.receipts.enrollment.phase = 132;
        self.send(&Packet::V3EnrollmentDisplay {
            presentation: p.clone(),
        })?;
        Ok(p)
    }
    pub fn report_v3_enrolled(&mut self) -> Result<()> {
        let slot = &mut self.v3_entry.receipts.enrollment;
        let b = slot
            .binding
            .as_ref()
            .ok_or_else(|| rejected("fresh receipt report before offer"))?;
        if slot.reported || slot.phase != 133 || self.core.phase.phase(self.target.index()) != 134 {
            return Err(rejected(
                "fresh receipt report before actual finished effect",
            ));
        }
        let data = SignerV3EnrollmentCommittedV1 {
            presentation_digest: b.p.presentation_digest.clone(),
            record_reference: b.p.facts.record_reference.clone(),
        };
        slot.reported = true;
        slot.phase = 134;
        self.send(&Packet::V3Enrolled {
            role: self.target,
            data,
        })
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_v3_enrollment(
        &self,
        mut ticket: SignerV3EnrollmentTicketV1,
    ) -> Result<SignerV3EnrollmentOutboundV1> {
        if !Arc::ptr_eq(&self.core, &ticket.binding.pair.entry.core) {
            self.revoke();
            return Err(rejected("fresh receipt foreign native Core"));
        }
        ticket.check_current()?;
        self.core
            .phase
            .step(ticket.binding.pair.entry.slot(), 132, 133)?;
        ticket.consumed = true;
        Ok(SignerV3EnrollmentOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn send_v3_enrollment(&mut self, out: SignerV3EnrollmentOutboundV1) -> Result<()> {
        self.try_send_v3_enrollment(out)?.require_sent()
    }
    pub fn try_send_v3_enrollment(
        &mut self,
        mut out: SignerV3EnrollmentOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = Arc::clone(&out.binding);
        let i = b.pair.entry.slot();
        let r = (|| {
            let slot = &self.v3_entries[i].receipts.enrollment;
            if !Arc::ptr_eq(&self.core, &b.pair.entry.core)
                || slot.phase != 132
                || slot
                    .binding
                    .as_ref()
                    .is_none_or(|old| !Arc::ptr_eq(old, &b))
            {
                return Err(rejected("fresh receipt outbound foreign/reused"));
            }
            b.bounds()?;
            if self.core.phase.source_send_restricted(i, 133)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::V3EnrollmentFinal {
                    role: b.p.actor.signer_role,
                    presentation_digest: b.p.presentation_digest.clone(),
                },
                b.deadline,
            )?;
            if r == FinancialSendProgressV1::Sent {
                self.v3_entries[i].receipts.enrollment.phase = 133;
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

const MANIFEST_REVIEW: u8 = 135;
const MANIFEST_ADMITTED: u8 = 136;
const MANIFEST_DONE: u8 = 137;
#[derive(Default)]
struct ManifestSlot {
    binding: Option<Arc<ManifestBinding>>,
    wire: Option<SignerV3ManifestPresentationV1>,
    phase: u8,
    reported: bool,
}
struct ManifestBinding {
    pair: Arc<PairBinding>,
    p: SignerV3ManifestPresentationV1,
    deadline: Instant,
    last_wall: AtomicU64,
}
impl ManifestBinding {
    fn new(pair: Arc<PairBinding>, p: SignerV3ManifestPresentationV1) -> Result<Arc<Self>> {
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
            return Err(rejected("fresh receipt review expired"));
        }
        Ok(())
    }
    fn current(&self, phase: u8) -> Result<()> {
        self.bounds()?;
        self.pair.entry.core.check_action_restrictions()?;
        if self.pair.entry.core.phase.phase(self.pair.entry.slot()) != phase {
            return Err(rejected("fresh receipt purpose consumed"));
        }
        Ok(())
    }
}
pub struct SignerV3ManifestTicketV1 {
    binding: Arc<ManifestBinding>,
    consumed: bool,
}
impl SignerV3ManifestTicketV1 {
    pub fn presentation(&self) -> &SignerV3ManifestPresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(135)
    }
}
impl Drop for SignerV3ManifestTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3ManifestOutboundV1 {
    binding: Arc<ManifestBinding>,
    consumed: bool,
}
impl Drop for SignerV3ManifestOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3ManifestFinalV1 {
    effect: AtomicU8,
    binding: Arc<ManifestBinding>,
    consumed: bool,
}
impl SignerV3ManifestFinalV1 {
    pub fn presentation(&self) -> &SignerV3ManifestPresentationV1 {
        &self.binding.p
    }
    pub fn facts(&self) -> &SignerV3ManifestFactsV1 {
        &self.binding.p.facts
    }
    pub fn original_review_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.pair.entry.original_source
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(136)
    }
    /// Invoke only under actual validated source/SQL locks. Move the entire
    /// owned transaction into this closure: commit, rollback and destruction
    /// must finish before it returns. No await, enqueue, or escaping guard.
    pub fn execute_manifest_publication(
        &self,
        publication: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.check_current()?;
        self.effect
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                self.binding.pair.entry.core.phase.revoke();
                rejected("fresh receipt publication is one-use")
            })?;
        let core = &self.binding.pair.entry.core;
        let mut attempt = ReceiptEffectAttempt {
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
    pub fn finish_review(mut self) -> Result<()> {
        let core = &self.binding.pair.entry.core;
        if self.effect.load(Ordering::Acquire) != 2
            || unsafe { libc::getpid() } != core.owner_pid
            || unsafe { libc::geteuid() } != core.owner_uid
            || core.phase.phase(self.binding.pair.entry.slot()) != 136
        {
            return Err(rejected(
                "fresh receipt finish lacks completed original publication",
            ));
        }
        core.phase
            .observe_v3_manifest_published(self.binding.pair.entry.slot())?;
        self.consumed = true;
        Ok(())
    }
}
impl Drop for SignerV3ManifestFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
fn manifest_matches(
    p: &SignerV3ManifestPresentationV1,
    entry: &SignerV3SourceEntryPresentationV1,
    pair: &SignerV3PairPresentationV1,
    result: &SignerV3PairedV1,
    prior: Option<&SignerV3EnrollmentPresentationV1>,
) -> bool {
    let f = &p.facts;
    p.actor == entry.actor
        && p.source_ceiling_ms == entry.source_ceiling_ms
        && p.review_ceiling_ms <= pair.channel_ceiling_ms
        && f.entry_presentation_digest == entry.presentation_digest
        && f.source_identity_digest == result.source_identity_digest
        && f.pair_grant_id == result.grant_id
        && f.pair_key_digest == result.key_digest
        && f.pair_channel_digest == result.channel_digest
        && f.pair_generation == result.generation
        && f.source_expires_at_ms == entry.facts.source_expires_at_ms
        && f.expires_at_ms <= pair.facts.channel_expires_at_ms
        && f.reviewed_at_ms >= pair.facts.reviewed_at_ms
        && (prior.is_some_and(|p| {
            f.current_enrollment_ref == p.facts.record_reference
                && f.coordinated_session_id == p.facts.coordinated_session_id
                && f.receipt_nonce != p.facts.receipt_nonce
        }))
}
impl SignerFinancialWorkflowOriginV1 {
    pub fn offer_v3_manifest(
        &mut self,
        facts: SignerV3ManifestFactsV1,
        original_review: Instant,
    ) -> Result<SignerV3ManifestPresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        let s = &mut self.v3_entry;
        let pair = s
            .pair
            .binding
            .as_ref()
            .ok_or_else(|| rejected("fresh receipt before Pair"))?;
        pair.channel_bounds()?;
        let result = s
            .pair
            .result
            .as_ref()
            .ok_or_else(|| rejected("fresh receipt before possession proof"))?;
        if s.receipts.manifest.binding.is_some()
            || original_review > pair.channel_deadline
            || original_review > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected("fresh receipt one exact window"));
        }
        let mut p = SignerV3ManifestPresentationV1 {
            actor: pair.p.actor.clone(),
            facts,
            notice: MANIFEST_NOTICE.into(),
            challenge: state::nonce()?,
            source_ceiling_ms: pair.p.source_ceiling_ms,
            review_ceiling_ms: self
                .clocks
                .restrictive_offset(original_review, pair.channel_deadline)?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        if !manifest_matches(
            &p,
            &pair.entry.wire.presentation,
            &pair.p,
            result,
            s.receipts.enrollment.wire.as_ref(),
        ) || !s.receipts.enrollment.reported
        {
            return Err(rejected("fresh receipt original record/Pair predecessor"));
        }
        let binding = ManifestBinding::new(Arc::clone(pair), p.clone())?;
        self.core.phase.step(self.target.index(), 134, 135)?;
        s.receipts.manifest.binding = Some(binding);
        s.receipts.manifest.wire = Some(p.clone());
        s.receipts.manifest.phase = 135;
        self.send(&Packet::V3ManifestDisplay {
            presentation: p.clone(),
        })?;
        Ok(p)
    }
    pub fn report_v3_manifest_accepted(&mut self) -> Result<()> {
        let slot = &mut self.v3_entry.receipts.manifest;
        let b = slot
            .binding
            .as_ref()
            .ok_or_else(|| rejected("fresh receipt report before offer"))?;
        if slot.reported || slot.phase != 136 || self.core.phase.phase(self.target.index()) != 137 {
            return Err(rejected(
                "fresh receipt report before actual finished effect",
            ));
        }
        let data = SignerV3ManifestCommittedV1 {
            presentation_digest: b.p.presentation_digest.clone(),
            record_reference: b.p.facts.record_reference.clone(),
        };
        slot.reported = true;
        slot.phase = 137;
        self.send(&Packet::V3ManifestAccepted {
            role: self.target,
            data,
        })
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_v3_manifest(
        &self,
        mut ticket: SignerV3ManifestTicketV1,
    ) -> Result<SignerV3ManifestOutboundV1> {
        if !Arc::ptr_eq(&self.core, &ticket.binding.pair.entry.core) {
            self.revoke();
            return Err(rejected("fresh receipt foreign native Core"));
        }
        ticket.check_current()?;
        self.core
            .phase
            .step(ticket.binding.pair.entry.slot(), 135, 136)?;
        ticket.consumed = true;
        Ok(SignerV3ManifestOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn send_v3_manifest(&mut self, out: SignerV3ManifestOutboundV1) -> Result<()> {
        self.try_send_v3_manifest(out)?.require_sent()
    }
    pub fn try_send_v3_manifest(
        &mut self,
        mut out: SignerV3ManifestOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = Arc::clone(&out.binding);
        let i = b.pair.entry.slot();
        let r = (|| {
            let slot = &self.v3_entries[i].receipts.manifest;
            if !Arc::ptr_eq(&self.core, &b.pair.entry.core)
                || slot.phase != 135
                || slot
                    .binding
                    .as_ref()
                    .is_none_or(|old| !Arc::ptr_eq(old, &b))
            {
                return Err(rejected("fresh receipt outbound foreign/reused"));
            }
            b.bounds()?;
            if self.core.phase.source_send_restricted(i, 136)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::V3ManifestFinal {
                    role: b.p.actor.signer_role,
                    presentation_digest: b.p.presentation_digest.clone(),
                },
                b.deadline,
            )?;
            if r == FinancialSendProgressV1::Sent {
                self.v3_entries[i].receipts.manifest.phase = 136;
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
    pub(in crate::financial_workflow_origin) fn receive_v3_receipt(
        &mut self,
        p: Packet,
    ) -> Result<SignerFinancialWorkflowRequestV1> {
        match p {
            Packet::V3EnrollmentFinal {
                role,
                presentation_digest,
            } => {
                let slot = &mut self.v3_entry.receipts.enrollment;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("fresh receipt Final unsolicited"))?;
                if role != self.target
                    || slot.phase != 132
                    || presentation_digest != b.p.presentation_digest
                {
                    return Err(rejected("fresh receipt Final mismatch/replay"));
                }
                b.current(132)?;
                self.core.phase.step(role.index(), 132, 133)?;
                slot.phase = 133;
                Ok(SignerFinancialWorkflowRequestV1::V3Enrollment {
                    final_action: SignerV3EnrollmentFinalV1 {
                        effect: AtomicU8::new(0),
                        binding: Arc::clone(b),
                        consumed: false,
                    },
                })
            }
            Packet::V3ManifestFinal {
                role,
                presentation_digest,
            } => {
                let slot = &mut self.v3_entry.receipts.manifest;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("fresh receipt Final unsolicited"))?;
                if role != self.target
                    || slot.phase != 135
                    || presentation_digest != b.p.presentation_digest
                {
                    return Err(rejected("fresh receipt Final mismatch/replay"));
                }
                b.current(135)?;
                self.core.phase.step(role.index(), 135, 136)?;
                slot.phase = 136;
                Ok(SignerFinancialWorkflowRequestV1::V3Manifest {
                    final_action: SignerV3ManifestFinalV1 {
                        effect: AtomicU8::new(0),
                        binding: Arc::clone(b),
                        consumed: false,
                    },
                })
            }
            _ => Err(rejected("wrong fresh receipt request")),
        }
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub(in crate::financial_workflow_origin) fn receive_v3_receipt_event(
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
        match p {
            Packet::V3EnrollmentDisplay { presentation } => {
                let slot = &s.receipts.enrollment;
                if slot.binding.is_some()
                    || !enrollment_matches(
                        &presentation,
                        &pair.entry.wire.presentation,
                        &pair.p,
                        result,
                        s.receipts.enrollment.wire.as_ref(),
                    )
                {
                    return Err(rejected("fresh receipt display predecessor"));
                }
                let b = EnrollmentBinding::new(Arc::clone(pair), presentation.clone())?;
                s.receipts.enrollment.wire = Some(presentation);
                s.receipts.enrollment.binding = Some(Arc::clone(&b));
                s.receipts.enrollment.phase = 132;
                if !received_workflow_progress(&self.core.phase, i, 131, 132)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::V3EnrollmentDisplay(
                    SignerV3EnrollmentTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::V3Enrolled { data, .. } => {
                data.validate()?;
                let slot = &mut s.receipts.enrollment;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("receipt result without review"))?;
                if slot.reported
                    || slot.phase != 133
                    || data.presentation_digest != b.p.presentation_digest
                    || data.record_reference != b.p.facts.record_reference
                {
                    return Err(rejected("receipt result binding/replay"));
                }
                slot.phase = 134;
                slot.reported = true;
                received_workflow_progress(&self.core.phase, i, 133, 134)?;
                Ok(CoordinatorFinancialEventV1::V3Enrolled { role, data })
            }
            Packet::V3ManifestDisplay { presentation } => {
                let slot = &s.receipts.manifest;
                if slot.binding.is_some()
                    || !manifest_matches(
                        &presentation,
                        &pair.entry.wire.presentation,
                        &pair.p,
                        result,
                        s.receipts.enrollment.wire.as_ref(),
                    )
                    || !s.receipts.enrollment.reported
                {
                    return Err(rejected("fresh receipt display predecessor"));
                }
                let b = ManifestBinding::new(Arc::clone(pair), presentation.clone())?;
                s.receipts.manifest.wire = Some(presentation);
                s.receipts.manifest.binding = Some(Arc::clone(&b));
                s.receipts.manifest.phase = 135;
                if !received_workflow_progress(&self.core.phase, i, 134, 135)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::V3ManifestDisplay(
                    SignerV3ManifestTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::V3ManifestAccepted { data, .. } => {
                data.validate()?;
                let slot = &mut s.receipts.manifest;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("receipt result without review"))?;
                if slot.reported
                    || slot.phase != 136
                    || data.presentation_digest != b.p.presentation_digest
                    || data.record_reference != b.p.facts.record_reference
                {
                    return Err(rejected("receipt result binding/replay"));
                }
                slot.phase = 137;
                slot.reported = true;
                received_workflow_progress(&self.core.phase, i, 136, 137)?;
                Ok(CoordinatorFinancialEventV1::V3ManifestAccepted { role, data })
            }
            _ => Err(rejected("wrong fresh receipt event")),
        }
    }
}
impl HostFinancialWorkflowRelayV1 {
    pub(in crate::financial_workflow_origin) fn down_v3_receipt(
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
            Packet::V3EnrollmentFinal {
                presentation_digest,
                ..
            } => {
                let slot = &mut s.receipts.enrollment;
                let p = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("receipt relay Final before display"))?;
                if slot.phase != 132 || presentation_digest != &p.presentation_digest {
                    return Err(rejected("receipt relay Final mismatch/replay"));
                }
                receipt_relay_clock(
                    p.review_ceiling_ms,
                    p.facts.reviewed_at_ms,
                    p.facts.expires_at_ms,
                    pair,
                    self.clocks,
                    &mut s.pair.last_wall,
                )?;
                slot.phase = 133;
                Ok(())
            }
            Packet::V3ManifestFinal {
                presentation_digest,
                ..
            } => {
                let slot = &mut s.receipts.manifest;
                let p = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("receipt relay Final before display"))?;
                if slot.phase != 135 || presentation_digest != &p.presentation_digest {
                    return Err(rejected("receipt relay Final mismatch/replay"));
                }
                receipt_relay_clock(
                    p.review_ceiling_ms,
                    p.facts.reviewed_at_ms,
                    p.facts.expires_at_ms,
                    pair,
                    self.clocks,
                    &mut s.pair.last_wall,
                )?;
                slot.phase = 136;
                Ok(())
            }
            _ => Err(rejected("wrong fresh receipt relay command")),
        }
    }
    pub(in crate::financial_workflow_origin) fn up_v3_receipt(
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
        match p {
            Packet::V3EnrollmentDisplay { presentation } => {
                presentation.validate()?;
                if s.receipts.enrollment.wire.is_some()
                    || !enrollment_matches(
                        presentation,
                        &entry.presentation,
                        pair,
                        result,
                        s.receipts.enrollment.wire.as_ref(),
                    )
                {
                    return Err(rejected("receipt relay display predecessor"));
                }
                if !self.restricted {
                    receipt_relay_clock(
                        presentation.review_ceiling_ms,
                        presentation.facts.reviewed_at_ms,
                        presentation.facts.expires_at_ms,
                        pair,
                        self.clocks,
                        &mut s.pair.last_wall,
                    )?;
                }
                s.receipts.enrollment.wire = Some(presentation.clone());
                s.receipts.enrollment.phase = 132;
                Ok(!self.restricted)
            }
            Packet::V3Enrolled { data, .. } => {
                data.validate()?;
                let slot = &mut s.receipts.enrollment;
                let p = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("receipt relay result before display"))?;
                if slot.reported
                    || slot.phase != 133
                    || data.presentation_digest != p.presentation_digest
                    || data.record_reference != p.facts.record_reference
                {
                    return Err(rejected("receipt relay result mismatch/replay"));
                }
                slot.reported = true;
                slot.phase = 134;
                Ok(true)
            }
            Packet::V3ManifestDisplay { presentation } => {
                presentation.validate()?;
                if s.receipts.manifest.wire.is_some()
                    || !manifest_matches(
                        presentation,
                        &entry.presentation,
                        pair,
                        result,
                        s.receipts.enrollment.wire.as_ref(),
                    )
                    || !s.receipts.enrollment.reported
                {
                    return Err(rejected("receipt relay display predecessor"));
                }
                if !self.restricted {
                    receipt_relay_clock(
                        presentation.review_ceiling_ms,
                        presentation.facts.reviewed_at_ms,
                        presentation.facts.expires_at_ms,
                        pair,
                        self.clocks,
                        &mut s.pair.last_wall,
                    )?;
                }
                s.receipts.manifest.wire = Some(presentation.clone());
                s.receipts.manifest.phase = 135;
                Ok(!self.restricted)
            }
            Packet::V3ManifestAccepted { data, .. } => {
                data.validate()?;
                let slot = &mut s.receipts.manifest;
                let p = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("receipt relay result before display"))?;
                if slot.reported
                    || slot.phase != 136
                    || data.presentation_digest != p.presentation_digest
                    || data.record_reference != p.facts.record_reference
                {
                    return Err(rejected("receipt relay result mismatch/replay"));
                }
                let disclosure = SignerV3CurrentDisclosureV1 {
                    source_identity_digest: p.facts.source_identity_digest.clone(),
                    entry_presentation_digest: p.facts.entry_presentation_digest.clone(),
                    pair_presentation_digest: pair.presentation_digest.clone(),
                    pair_grant_id: result.grant_id.clone(),
                    coordinated_session_id: p.facts.coordinated_session_id.clone(),
                    current_enrollment_ref: p.facts.current_enrollment_ref.clone(),
                    current_manifest_ref: data.record_reference.clone(),
                };
                disclosure.validate()?;
                if !self.restricted {
                    self.lifecycle
                        .publish_v3_current_disclosure(role, disclosure)?;
                }
                slot.reported = true;
                slot.phase = 137;
                Ok(true)
            }
            _ => Err(rejected("wrong fresh receipt relay event")),
        }
    }
}
fn receipt_relay_clock(
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
        return Err(rejected("fresh receipt original relay window"));
    }
    *last = wall;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fresh_receipt_purposes_do_not_reuse_pair_or_complete_v3() {
        let p = Phases::new();
        p.step(0, 0, 131).unwrap();
        p.step(0, 131, ENROLLMENT_REVIEW).unwrap();
        p.step(0, ENROLLMENT_REVIEW, ENROLLMENT_ADMITTED).unwrap();
        p.step(0, ENROLLMENT_ADMITTED, ENROLLMENT_DONE).unwrap();
        assert!(p.step(0, ENROLLMENT_ADMITTED, ENROLLMENT_DONE).is_err());
        p.step(0, ENROLLMENT_DONE, MANIFEST_REVIEW).unwrap();
        p.step(0, MANIFEST_REVIEW, MANIFEST_ADMITTED).unwrap();
        p.step(0, MANIFEST_ADMITTED, MANIFEST_DONE).unwrap();
        assert_ne!(p.phase(0), V3_HELD);
    }
    #[test]
    fn r_prevents_new_record_effect() {
        for phase in [ENROLLMENT_ADMITTED, MANIFEST_ADMITTED] {
            let p = Phases::new();
            p.step(0, 0, phase).unwrap();
            p.revoke();
            assert!(p.step(0, phase, phase + 1).is_err());
        }
    }
}

// Pinned-S implementation boundary: this gate proves exclusive entry and the
// closure result, not physical SQL execution. Only the reviewed source kernel
// may invoke it, with an owned transaction moved into the synchronous closure.
struct ReceiptEffectAttempt<'a> {
    core: &'a Core,
    effect: &'a AtomicU8,
    settled: bool,
}
impl Drop for ReceiptEffectAttempt<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.effect.store(3, Ordering::Release);
            self.core.phase.revoke();
        }
    }
}

impl ReceiptSlots {
    pub(super) fn current_disclosure(
        &self,
        pair: &SignerV3PairPresentationV1,
        result: &SignerV3PairedV1,
    ) -> Result<SignerV3CurrentDisclosureV1> {
        let e = self
            .enrollment
            .wire
            .as_ref()
            .ok_or_else(|| rejected("current disclosure without fresh enrollment"))?;
        let m = self
            .manifest
            .wire
            .as_ref()
            .ok_or_else(|| rejected("current disclosure without fresh manifest"))?;
        if !self.enrollment.reported
            || !self.manifest.reported
            || m.facts.current_enrollment_ref != e.facts.record_reference
            || m.facts.coordinated_session_id != e.facts.coordinated_session_id
        {
            return Err(rejected("current disclosure requires both actual commits"));
        }
        let data = SignerV3CurrentDisclosureV1 {
            source_identity_digest: m.facts.source_identity_digest.clone(),
            entry_presentation_digest: m.facts.entry_presentation_digest.clone(),
            pair_presentation_digest: pair.presentation_digest.clone(),
            pair_grant_id: result.grant_id.clone(),
            coordinated_session_id: m.facts.coordinated_session_id.clone(),
            current_enrollment_ref: e.facts.record_reference.clone(),
            current_manifest_ref: m.facts.record_reference.clone(),
        };
        data.validate()?;
        Ok(data)
    }
}
