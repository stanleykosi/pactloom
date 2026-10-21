//! Distinct private preparation Read and exact one-payload Receive.
use super::pair::PairBinding;
use super::*;
use crate::signer_v3_delivery_data::*;
use crate::signer_v3_pair_data::{SignerV3PairPresentationV1, SignerV3PairedV1};
use crate::SignerV3CurrentDisclosureV1;
#[derive(Default)]
pub(super) struct DeliverySlots {
    owner_selection: Option<OwnerSelection>,
    prepare_read: PrepareReadSlot,
    receive: ReceiveSlot,
}

const PREPARE_READ_REVIEW: u8 = 144;
const PREPARE_READ_ADMITTED: u8 = 145;
const PREPARE_READ_DONE: u8 = 146;
#[derive(Default)]
struct PrepareReadSlot {
    prepared: Option<SignerV3PreparedV1>,
    binding: Option<Arc<PrepareReadBinding>>,
    wire: Option<SignerV3PrepareReadPresentationV1>,
    phase: u8,
    reported: bool,
}
struct PrepareReadBinding {
    service_deadline: Instant,
    material_deadline: Instant,
    pair: Arc<PairBinding>,
    p: SignerV3PrepareReadPresentationV1,
    deadline: Instant,
    last_wall: AtomicU64,
}
impl PrepareReadBinding {
    fn new(pair: Arc<PairBinding>, p: SignerV3PrepareReadPresentationV1) -> Result<Arc<Self>> {
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
        let service_deadline = pair
            .entry
            .clocks
            .restrict_received(PROFILE, p.service_ceiling_ms, pair.channel_deadline, now)?
            .min(wall_ceiling(
                now,
                state::wall_ms()?,
                p.facts.reviewed_at_ms,
                p.facts.service_expires_at_ms,
            )?);
        let material_deadline = pair
            .entry
            .clocks
            .restrict_received(PROFILE, p.material_ceiling_ms, pair.channel_deadline, now)?
            .min(wall_ceiling(
                now,
                state::wall_ms()?,
                p.facts.reviewed_at_ms,
                p.facts.material_expires_at_ms,
            )?);
        let b = Arc::new(Self {
            service_deadline,
            material_deadline,
            pair,
            p,
            deadline,
            last_wall: AtomicU64::new(state::wall_ms()?),
        });
        b.bounds()?;
        Ok(b)
    }
    fn bounds(&self) -> Result<()> {
        self.custody_bounds()?;
        let wall = state::wall_ms()?;
        let old = self.last_wall.fetch_max(wall, Ordering::AcqRel);
        if wall < old
            || wall < self.p.facts.reviewed_at_ms
            || wall >= self.p.facts.expires_at_ms
            || Instant::now() >= self.deadline
        {
            return Err(rejected("delivery review expired"));
        }
        Ok(())
    }
    fn custody_bounds(&self) -> Result<()> {
        self.pair.channel_bounds()?;
        let wall = state::wall_ms()?;
        let old = self.last_wall.fetch_max(wall, Ordering::AcqRel);
        if wall < old
            || wall >= self.p.facts.service_expires_at_ms
            || wall >= self.p.facts.material_expires_at_ms
            || Instant::now() >= self.service_deadline
            || Instant::now() >= self.material_deadline
        {
            return Err(rejected("original delivery service/material bound"));
        }
        Ok(())
    }
    fn current(&self, phase: u8) -> Result<()> {
        self.bounds()?;
        self.pair.entry.core.check_action_restrictions()?;
        if self.pair.entry.core.phase.phase(self.pair.entry.slot()) != phase {
            return Err(rejected("delivery purpose consumed"));
        }
        Ok(())
    }
}
pub struct SignerV3PrepareReadTicketV1 {
    binding: Arc<PrepareReadBinding>,
    consumed: bool,
}
impl SignerV3PrepareReadTicketV1 {
    pub fn presentation(&self) -> &SignerV3PrepareReadPresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(144)
    }
}
impl Drop for SignerV3PrepareReadTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3PrepareReadOutboundV1 {
    binding: Arc<PrepareReadBinding>,
    consumed: bool,
}
impl Drop for SignerV3PrepareReadOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3PrepareReadFinalV1 {
    binding: Arc<PrepareReadBinding>,
    consumed: bool,
}
impl SignerV3PrepareReadFinalV1 {
    pub fn original_channel_deadline(&self) -> Instant {
        self.binding.pair.channel_deadline
    }
    pub fn original_service_deadline(&self) -> Instant {
        self.binding.service_deadline
    }
    pub fn original_material_deadline(&self) -> Instant {
        self.binding.material_deadline
    }
    pub fn presentation(&self) -> &SignerV3PrepareReadPresentationV1 {
        &self.binding.p
    }
    pub fn facts(&self) -> &SignerV3PrepareReadFactsV1 {
        &self.binding.p.facts
    }
    pub fn original_review_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.pair.entry.original_source
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(145)
    }
    pub fn original_read_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn into_prepared_custody_lifetime(mut self) -> Result<SignerV3PreparedLifetimeV1> {
        self.check_current()?;
        self.binding
            .pair
            .entry
            .core
            .phase
            .step(self.binding.pair.entry.slot(), 145, 146)?;
        self.consumed = true;
        Ok(SignerV3PreparedLifetimeV1 {
            binding: Arc::clone(&self.binding),
        })
    }
}
impl Drop for SignerV3PrepareReadFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
fn prepare_read_matches(
    p: &SignerV3PrepareReadPresentationV1,
    entry: &SignerV3SourceEntryPresentationV1,
    pair: &SignerV3PairPresentationV1,
    result: &SignerV3PairedV1,
    current: &SignerV3CurrentDisclosureV1,
    export: &crate::SignerV3RedisclosedV1,
    selected: Option<&OwnerSelection>,
    read: Option<&SignerV3PrepareReadPresentationV1>,
    prepared: Option<&SignerV3PreparedV1>,
) -> bool {
    let f = &p.facts;
    p.actor == entry.actor
        && p.source_ceiling_ms == entry.source_ceiling_ms
        && p.review_ceiling_ms <= pair.channel_ceiling_ms
        && p.service_ceiling_ms <= pair.channel_ceiling_ms
        && p.material_ceiling_ms <= pair.channel_ceiling_ms
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
        && f.service_expires_at_ms <= pair.facts.channel_expires_at_ms
        && f.material_expires_at_ms <= pair.facts.channel_expires_at_ms
        && f.reviewed_at_ms >= pair.facts.reviewed_at_ms
        && f.current_outbox_reference == export.outbox_reference
        && f.current_request_digest == export.request_digest
        && f.original_host_process_instance == pair.facts.original_host_process_instance
        && f.coordinated_provider_reference == pair.facts.coordinated_provider_reference
        && f.owner_certificate_digest == entry.facts.owner_certificate_digest
        && SignerV3OwnerSetupSelectionV1::parse_json(&f.owner_setup_json)
            .is_ok_and(|v| v.account_id == entry.facts.account_id)
        && selected.is_some_and(|v| {
            v.json == f.owner_setup_json
                && v.challenge == f.owner_selection_challenge
                && v.source == f.source_identity_digest
                && v.export == export.presentation_digest
        })
}

impl SignerFinancialWorkflowOriginV1 {
    pub fn offer_v3_prepare_read(
        &mut self,
        facts: SignerV3PrepareReadFactsV1,
        original_review: Instant,
        original_service: Instant,
        original_material: Instant,
    ) -> Result<SignerV3PrepareReadPresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        let s = &mut self.v3_entry;
        let pair = s
            .pair
            .binding
            .as_ref()
            .ok_or_else(|| rejected("delivery before Pair"))?;
        pair.channel_bounds()?;
        let result = s
            .pair
            .result
            .as_ref()
            .ok_or_else(|| rejected("delivery before possession proof"))?;
        let current = s.receipts.current_disclosure(&pair.p, result)?;
        let export = s.redisclosure.actual_export()?;
        if s.delivery.prepare_read.binding.is_some()
            || original_review > pair.channel_deadline
            || original_review > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected("delivery one exact window"));
        }
        if original_service > pair.channel_deadline
            || original_material > pair.channel_deadline
            || original_review > original_service
            || original_review > original_material
        {
            return Err(rejected("original preparation ceilings"));
        }
        let mut p = SignerV3PrepareReadPresentationV1 {
            actor: pair.p.actor.clone(),
            facts,
            notice: PREPARE_READ_NOTICE.into(),
            challenge: state::nonce()?,
            source_ceiling_ms: pair.p.source_ceiling_ms,
            service_ceiling_ms: self
                .clocks
                .restrictive_offset(original_service, pair.channel_deadline)?,
            material_ceiling_ms: self
                .clocks
                .restrictive_offset(original_material, pair.channel_deadline)?,
            review_ceiling_ms: self
                .clocks
                .restrictive_offset(original_review, pair.channel_deadline)?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        if !prepare_read_matches(
            &p,
            &pair.entry.wire.presentation,
            &pair.p,
            result,
            &current,
            export,
            s.delivery.owner_selection.as_ref(),
            s.delivery.prepare_read.wire.as_ref(),
            s.delivery.prepare_read.prepared.as_ref(),
        ) {
            return Err(rejected("delivery original record/Pair predecessor"));
        }
        let mut binding = PrepareReadBinding::new(Arc::clone(pair), p.clone())?;
        {
            let b = Arc::get_mut(&mut binding)
                .ok_or_else(|| rejected("new delivery binding shared"))?;
            b.deadline = original_review;
            b.service_deadline = original_service;
            b.material_deadline = original_material;
            b.bounds()?;
        }
        self.core.phase.step(self.target.index(), 143, 144)?;
        s.delivery.prepare_read.binding = Some(binding);
        s.delivery.prepare_read.wire = Some(p.clone());
        s.delivery.prepare_read.phase = 144;
        self.send(&Packet::V3PrepareReadDisplay {
            presentation: p.clone(),
        })?;
        Ok(p)
    }
    pub fn report_v3_prepared(&mut self, data: SignerV3PreparedV1) -> Result<()> {
        data.validate()?;
        let slot = &mut self.v3_entry.delivery.prepare_read;
        let b = slot
            .binding
            .as_ref()
            .ok_or_else(|| rejected("delivery report before offer"))?;
        if slot.reported
            || slot.phase != 145
            || self.core.phase.phase(self.target.index()) != 146
            || !prepared_matches(&data, &b.p)
        {
            return Err(rejected("delivery actual result binding/replay"));
        }
        slot.prepared = Some(data.clone());
        slot.reported = true;
        slot.phase = 146;
        self.send(&Packet::V3Prepared {
            role: self.target,
            data,
        })
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_v3_prepare_read(
        &self,
        mut ticket: SignerV3PrepareReadTicketV1,
    ) -> Result<SignerV3PrepareReadOutboundV1> {
        if !Arc::ptr_eq(&self.core, &ticket.binding.pair.entry.core) {
            self.revoke();
            return Err(rejected("delivery foreign native Core"));
        }
        ticket.check_current()?;
        self.core
            .phase
            .step(ticket.binding.pair.entry.slot(), 144, 145)?;
        ticket.consumed = true;
        Ok(SignerV3PrepareReadOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn send_v3_prepare_read(&mut self, out: SignerV3PrepareReadOutboundV1) -> Result<()> {
        self.try_send_v3_prepare_read(out)?.require_sent()
    }
    pub fn try_send_v3_prepare_read(
        &mut self,
        mut out: SignerV3PrepareReadOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = Arc::clone(&out.binding);
        let i = b.pair.entry.slot();
        let r = (|| {
            let slot = &self.v3_entries[i].delivery.prepare_read;
            if !Arc::ptr_eq(&self.core, &b.pair.entry.core)
                || slot.phase != 144
                || slot
                    .binding
                    .as_ref()
                    .is_none_or(|old| !Arc::ptr_eq(old, &b))
            {
                return Err(rejected("delivery outbound foreign/reused"));
            }
            b.bounds()?;
            if self.core.phase.source_send_restricted(i, 145)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::V3PrepareReadFinal {
                    role: b.p.actor.signer_role,
                    presentation_digest: b.p.presentation_digest.clone(),
                },
                b.deadline,
            )?;
            if r == FinancialSendProgressV1::Sent {
                self.v3_entries[i].delivery.prepare_read.phase = 145;
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

const RECEIVE_REVIEW: u8 = 147;
const RECEIVE_ADMITTED: u8 = 148;
const RECEIVE_DONE: u8 = 149;
#[derive(Default)]
struct ReceiveSlot {
    result: Option<SignerV3ReceivedV1>,
    binding: Option<Arc<ReceiveBinding>>,
    wire: Option<SignerV3ReceivePresentationV1>,
    phase: u8,
    reported: bool,
}
struct ReceiveBinding {
    service_deadline: Instant,
    material_deadline: Instant,
    pair: Arc<PairBinding>,
    p: SignerV3ReceivePresentationV1,
    deadline: Instant,
    last_wall: AtomicU64,
}
impl ReceiveBinding {
    fn new(pair: Arc<PairBinding>, p: SignerV3ReceivePresentationV1) -> Result<Arc<Self>> {
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
        let service_deadline = pair
            .entry
            .clocks
            .restrict_received(PROFILE, p.service_ceiling_ms, pair.channel_deadline, now)?
            .min(wall_ceiling(
                now,
                state::wall_ms()?,
                p.facts.reviewed_at_ms,
                p.facts.service_expires_at_ms,
            )?);
        let material_deadline = pair
            .entry
            .clocks
            .restrict_received(PROFILE, p.material_ceiling_ms, pair.channel_deadline, now)?
            .min(wall_ceiling(
                now,
                state::wall_ms()?,
                p.facts.reviewed_at_ms,
                p.facts.material_expires_at_ms,
            )?);
        let b = Arc::new(Self {
            service_deadline,
            material_deadline,
            pair,
            p,
            deadline,
            last_wall: AtomicU64::new(state::wall_ms()?),
        });
        b.bounds()?;
        Ok(b)
    }
    fn bounds(&self) -> Result<()> {
        self.custody_bounds()?;
        let wall = state::wall_ms()?;
        let old = self.last_wall.fetch_max(wall, Ordering::AcqRel);
        if wall < old
            || wall < self.p.facts.reviewed_at_ms
            || wall >= self.p.facts.expires_at_ms
            || Instant::now() >= self.deadline
        {
            return Err(rejected("delivery review expired"));
        }
        Ok(())
    }
    fn custody_bounds(&self) -> Result<()> {
        self.pair.channel_bounds()?;
        let wall = state::wall_ms()?;
        let old = self.last_wall.fetch_max(wall, Ordering::AcqRel);
        if wall < old
            || wall >= self.p.facts.service_expires_at_ms
            || wall >= self.p.facts.material_expires_at_ms
            || Instant::now() >= self.service_deadline
            || Instant::now() >= self.material_deadline
        {
            return Err(rejected("original delivery service/material bound"));
        }
        Ok(())
    }
    fn current(&self, phase: u8) -> Result<()> {
        self.bounds()?;
        self.pair.entry.core.check_action_restrictions()?;
        if self.pair.entry.core.phase.phase(self.pair.entry.slot()) != phase {
            return Err(rejected("delivery purpose consumed"));
        }
        Ok(())
    }
}
pub struct SignerV3ReceiveTicketV1 {
    binding: Arc<ReceiveBinding>,
    consumed: bool,
}
impl SignerV3ReceiveTicketV1 {
    pub fn presentation(&self) -> &SignerV3ReceivePresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(147)
    }
}
impl Drop for SignerV3ReceiveTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3ReceiveOutboundV1 {
    binding: Arc<ReceiveBinding>,
    consumed: bool,
}
impl Drop for SignerV3ReceiveOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
pub struct SignerV3ReceiveFinalV1 {
    binding: Arc<ReceiveBinding>,
    consumed: bool,
}
impl SignerV3ReceiveFinalV1 {
    pub fn original_channel_deadline(&self) -> Instant {
        self.binding.pair.channel_deadline
    }
    pub fn original_service_deadline(&self) -> Instant {
        self.binding.service_deadline
    }
    pub fn original_material_deadline(&self) -> Instant {
        self.binding.material_deadline
    }
    pub fn presentation(&self) -> &SignerV3ReceivePresentationV1 {
        &self.binding.p
    }
    pub fn facts(&self) -> &SignerV3ReceiveFactsV1 {
        &self.binding.p.facts
    }
    pub fn original_review_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.pair.entry.original_source
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(148)
    }
    pub fn original_receive_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn finish_receive(mut self) -> Result<()> {
        self.check_current()?;
        self.binding
            .pair
            .entry
            .core
            .phase
            .step(self.binding.pair.entry.slot(), 148, 149)?;
        self.consumed = true;
        Ok(())
    }
}
impl Drop for SignerV3ReceiveFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.pair.entry.core.phase.revoke();
        }
    }
}
fn receive_matches(
    p: &SignerV3ReceivePresentationV1,
    entry: &SignerV3SourceEntryPresentationV1,
    pair: &SignerV3PairPresentationV1,
    result: &SignerV3PairedV1,
    current: &SignerV3CurrentDisclosureV1,
    export: &crate::SignerV3RedisclosedV1,
    selected: Option<&OwnerSelection>,
    read: Option<&SignerV3PrepareReadPresentationV1>,
    prepared: Option<&SignerV3PreparedV1>,
) -> bool {
    let f = &p.facts;
    p.actor == entry.actor
        && p.source_ceiling_ms == entry.source_ceiling_ms
        && p.review_ceiling_ms <= pair.channel_ceiling_ms
        && p.service_ceiling_ms <= pair.channel_ceiling_ms
        && p.material_ceiling_ms <= pair.channel_ceiling_ms
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
        && f.service_expires_at_ms <= pair.facts.channel_expires_at_ms
        && f.material_expires_at_ms <= pair.facts.channel_expires_at_ms
        && f.reviewed_at_ms >= pair.facts.reviewed_at_ms
        && f.current_outbox_reference == export.outbox_reference
        && f.current_request_digest == export.request_digest
        && f.original_host_process_instance == pair.facts.original_host_process_instance
        && f.coordinated_provider_reference == pair.facts.coordinated_provider_reference
        && prepared.is_some_and(|d| {
            d.owner_service_digest == f.owner_service_digest
                && d.read_session_digest == f.read_session_digest
                && d.preparation_digest == f.preparation_digest
                && d.prepare_read_presentation_digest == f.prepare_read_presentation_digest
        })
        && read.is_some_and(|r| {
            r.presentation_digest == f.prepare_read_presentation_digest
                && r.service_ceiling_ms == p.service_ceiling_ms
                && r.material_ceiling_ms == p.material_ceiling_ms
                && r.facts.preparation_digest == f.preparation_digest
                && r.facts.owner_selection_digest == f.owner_selection_digest
                && r.facts.owner_certificate_digest == f.owner_certificate_digest
                && r.facts.disclosure_digest == f.disclosure_digest
                && r.facts.payload_digest == f.payload_digest
                && r.facts.payload_bytes == f.payload_bytes
                && r.facts.fixed_identity_digest == f.fixed_identity_digest
                && r.facts.material_scopes_digest == f.material_scopes_digest
                && r.facts.service_expires_at_ms == f.service_expires_at_ms
                && r.facts.material_expires_at_ms == f.material_expires_at_ms
        })
}

impl SignerFinancialWorkflowOriginV1 {
    pub fn offer_v3_receive(
        &mut self,
        facts: SignerV3ReceiveFactsV1,
        original_review: Instant,
    ) -> Result<SignerV3ReceivePresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        let s = &mut self.v3_entry;
        let pair = s
            .pair
            .binding
            .as_ref()
            .ok_or_else(|| rejected("delivery before Pair"))?;
        pair.channel_bounds()?;
        let result = s
            .pair
            .result
            .as_ref()
            .ok_or_else(|| rejected("delivery before possession proof"))?;
        let current = s.receipts.current_disclosure(&pair.p, result)?;
        let export = s.redisclosure.actual_export()?;
        if s.delivery.receive.binding.is_some()
            || original_review > pair.channel_deadline
            || original_review > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected("delivery one exact window"));
        }
        let read = s
            .delivery
            .prepare_read
            .binding
            .as_ref()
            .ok_or_else(|| rejected("Receive before actual Read"))?;
        read.custody_bounds()?;
        let original_service = read.service_deadline;
        let original_material = read.material_deadline;
        if !s.delivery.prepare_read.reported
            || original_review > original_service
            || original_review > original_material
        {
            return Err(rejected("Receive original custody ceilings"));
        }
        let mut p = SignerV3ReceivePresentationV1 {
            actor: pair.p.actor.clone(),
            facts,
            notice: RECEIVE_NOTICE.into(),
            challenge: state::nonce()?,
            source_ceiling_ms: pair.p.source_ceiling_ms,
            service_ceiling_ms: read.p.service_ceiling_ms,
            material_ceiling_ms: read.p.material_ceiling_ms,
            review_ceiling_ms: self
                .clocks
                .restrictive_offset(original_review, pair.channel_deadline)?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        if !receive_matches(
            &p,
            &pair.entry.wire.presentation,
            &pair.p,
            result,
            &current,
            export,
            s.delivery.owner_selection.as_ref(),
            s.delivery.prepare_read.wire.as_ref(),
            s.delivery.prepare_read.prepared.as_ref(),
        ) || !s.delivery.prepare_read.reported
        {
            return Err(rejected("delivery original record/Pair predecessor"));
        }
        let mut binding = ReceiveBinding::new(Arc::clone(pair), p.clone())?;
        {
            let b = Arc::get_mut(&mut binding)
                .ok_or_else(|| rejected("new delivery binding shared"))?;
            b.deadline = original_review;
            b.service_deadline = original_service;
            b.material_deadline = original_material;
            b.bounds()?;
        }
        self.core.phase.step(self.target.index(), 146, 147)?;
        s.delivery.receive.binding = Some(binding);
        s.delivery.receive.wire = Some(p.clone());
        s.delivery.receive.phase = 147;
        self.send(&Packet::V3ReceiveDisplay {
            presentation: p.clone(),
        })?;
        Ok(p)
    }
    pub fn report_v3_received(&mut self, data: SignerV3ReceivedV1) -> Result<()> {
        data.validate()?;
        let slot = &mut self.v3_entry.delivery.receive;
        let b = slot
            .binding
            .as_ref()
            .ok_or_else(|| rejected("delivery report before offer"))?;
        if slot.reported
            || slot.phase != 148
            || self.core.phase.phase(self.target.index()) != 149
            || !received_matches(&data, &b.p)
        {
            return Err(rejected("delivery actual result binding/replay"));
        }
        slot.result = Some(data.clone());
        slot.reported = true;
        slot.phase = 149;
        self.send(&Packet::V3Received {
            role: self.target,
            data,
        })
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_v3_receive(
        &self,
        mut ticket: SignerV3ReceiveTicketV1,
    ) -> Result<SignerV3ReceiveOutboundV1> {
        if !Arc::ptr_eq(&self.core, &ticket.binding.pair.entry.core) {
            self.revoke();
            return Err(rejected("delivery foreign native Core"));
        }
        ticket.check_current()?;
        self.core
            .phase
            .step(ticket.binding.pair.entry.slot(), 147, 148)?;
        ticket.consumed = true;
        Ok(SignerV3ReceiveOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn send_v3_receive(&mut self, out: SignerV3ReceiveOutboundV1) -> Result<()> {
        self.try_send_v3_receive(out)?.require_sent()
    }
    pub fn try_send_v3_receive(
        &mut self,
        mut out: SignerV3ReceiveOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = Arc::clone(&out.binding);
        let i = b.pair.entry.slot();
        let r = (|| {
            let slot = &self.v3_entries[i].delivery.receive;
            if !Arc::ptr_eq(&self.core, &b.pair.entry.core)
                || slot.phase != 147
                || slot
                    .binding
                    .as_ref()
                    .is_none_or(|old| !Arc::ptr_eq(old, &b))
            {
                return Err(rejected("delivery outbound foreign/reused"));
            }
            b.bounds()?;
            if self.core.phase.source_send_restricted(i, 148)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::V3ReceiveFinal {
                    role: b.p.actor.signer_role,
                    presentation_digest: b.p.presentation_digest.clone(),
                },
                b.deadline,
            )?;
            if r == FinancialSendProgressV1::Sent {
                self.v3_entries[i].delivery.receive.phase = 148;
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
    pub(in crate::financial_workflow_origin) fn receive_v3_delivery(
        &mut self,
        p: Packet,
    ) -> Result<SignerFinancialWorkflowRequestV1> {
        match p {
            Packet::V3PrepareReadFinal {
                role,
                presentation_digest,
            } => {
                let slot = &mut self.v3_entry.delivery.prepare_read;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("delivery Final unsolicited"))?;
                if role != self.target
                    || slot.phase != 144
                    || presentation_digest != b.p.presentation_digest
                {
                    return Err(rejected("delivery Final mismatch/replay"));
                }
                b.current(144)?;
                self.core.phase.step(role.index(), 144, 145)?;
                slot.phase = 145;
                Ok(SignerFinancialWorkflowRequestV1::V3PrepareRead {
                    final_action: SignerV3PrepareReadFinalV1 {
                        binding: Arc::clone(b),
                        consumed: false,
                    },
                })
            }
            Packet::V3ReceiveFinal {
                role,
                presentation_digest,
            } => {
                let slot = &mut self.v3_entry.delivery.receive;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("delivery Final unsolicited"))?;
                if role != self.target
                    || slot.phase != 147
                    || presentation_digest != b.p.presentation_digest
                {
                    return Err(rejected("delivery Final mismatch/replay"));
                }
                b.current(147)?;
                self.core.phase.step(role.index(), 147, 148)?;
                slot.phase = 148;
                Ok(SignerFinancialWorkflowRequestV1::V3Receive {
                    final_action: SignerV3ReceiveFinalV1 {
                        binding: Arc::clone(b),
                        consumed: false,
                    },
                })
            }
            _ => Err(rejected("wrong delivery request")),
        }
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub(in crate::financial_workflow_origin) fn receive_v3_delivery_event(
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
        let export = s.redisclosure.actual_export()?;
        match p {
            Packet::V3PrepareReadDisplay { presentation } => {
                let slot = &s.delivery.prepare_read;
                if slot.binding.is_some()
                    || !prepare_read_matches(
                        &presentation,
                        &pair.entry.wire.presentation,
                        &pair.p,
                        result,
                        &current,
                        export,
                        s.delivery.owner_selection.as_ref(),
                        s.delivery.prepare_read.wire.as_ref(),
                        s.delivery.prepare_read.prepared.as_ref(),
                    )
                {
                    return Err(rejected("delivery display predecessor"));
                }
                let b = PrepareReadBinding::new(Arc::clone(pair), presentation.clone())?;
                s.delivery.prepare_read.wire = Some(presentation);
                s.delivery.prepare_read.binding = Some(Arc::clone(&b));
                s.delivery.prepare_read.phase = 144;
                if !received_workflow_progress(&self.core.phase, i, 143, 144)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::V3PrepareReadDisplay(
                    SignerV3PrepareReadTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::V3Prepared { data, .. } => {
                data.validate()?;
                let slot = &mut s.delivery.prepare_read;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("receipt result without review"))?;
                if slot.reported || slot.phase != 145 || !prepared_matches(&data, &b.p) {
                    return Err(rejected("receipt result binding/replay"));
                }
                slot.prepared = Some(data.clone());
                slot.phase = 146;
                slot.reported = true;
                received_workflow_progress(&self.core.phase, i, 145, 146)?;
                Ok(CoordinatorFinancialEventV1::V3Prepared { role, data })
            }
            Packet::V3ReceiveDisplay { presentation } => {
                let slot = &s.delivery.receive;
                if slot.binding.is_some()
                    || !receive_matches(
                        &presentation,
                        &pair.entry.wire.presentation,
                        &pair.p,
                        result,
                        &current,
                        export,
                        s.delivery.owner_selection.as_ref(),
                        s.delivery.prepare_read.wire.as_ref(),
                        s.delivery.prepare_read.prepared.as_ref(),
                    )
                    || !s.delivery.prepare_read.reported
                {
                    return Err(rejected("delivery display predecessor"));
                }
                let b = ReceiveBinding::new(Arc::clone(pair), presentation.clone())?;
                s.delivery.receive.wire = Some(presentation);
                s.delivery.receive.binding = Some(Arc::clone(&b));
                s.delivery.receive.phase = 147;
                if !received_workflow_progress(&self.core.phase, i, 146, 147)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::V3ReceiveDisplay(
                    SignerV3ReceiveTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::V3Received { data, .. } => {
                data.validate()?;
                let slot = &mut s.delivery.receive;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("receipt result without review"))?;
                if slot.reported || slot.phase != 148 || !received_matches(&data, &b.p) {
                    return Err(rejected("receipt result binding/replay"));
                }
                slot.result = Some(data.clone());
                slot.phase = 149;
                slot.reported = true;
                received_workflow_progress(&self.core.phase, i, 148, 149)?;
                Ok(CoordinatorFinancialEventV1::V3Received { role, data })
            }
            _ => Err(rejected("wrong delivery event")),
        }
    }
}
impl HostFinancialWorkflowRelayV1 {
    pub(in crate::financial_workflow_origin) fn down_v3_delivery(
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
            Packet::V3PrepareReadFinal {
                presentation_digest,
                ..
            } => {
                let slot = &mut s.delivery.prepare_read;
                let p = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("receipt relay Final before display"))?;
                if slot.phase != 144 || presentation_digest != &p.presentation_digest {
                    return Err(rejected("receipt relay Final mismatch/replay"));
                }
                delivery_relay_clock(
                    p.review_ceiling_ms,
                    p.facts.reviewed_at_ms,
                    p.facts.expires_at_ms,
                    pair,
                    self.clocks,
                    &mut s.pair.last_wall,
                )?;
                slot.phase = 145;
                Ok(())
            }
            Packet::V3ReceiveFinal {
                presentation_digest,
                ..
            } => {
                let slot = &mut s.delivery.receive;
                let p = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("receipt relay Final before display"))?;
                if slot.phase != 147 || presentation_digest != &p.presentation_digest {
                    return Err(rejected("receipt relay Final mismatch/replay"));
                }
                delivery_relay_clock(
                    p.review_ceiling_ms,
                    p.facts.reviewed_at_ms,
                    p.facts.expires_at_ms,
                    pair,
                    self.clocks,
                    &mut s.pair.last_wall,
                )?;
                slot.phase = 148;
                Ok(())
            }
            _ => Err(rejected("wrong delivery relay command")),
        }
    }
    pub(in crate::financial_workflow_origin) fn up_v3_delivery(
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
        let export = s.redisclosure.actual_export()?;
        match p {
            Packet::V3PrepareReadDisplay { presentation } => {
                presentation.validate()?;
                if s.delivery.prepare_read.wire.is_some()
                    || !prepare_read_matches(
                        presentation,
                        &entry.presentation,
                        pair,
                        result,
                        &current,
                        export,
                        s.delivery.owner_selection.as_ref(),
                        s.delivery.prepare_read.wire.as_ref(),
                        s.delivery.prepare_read.prepared.as_ref(),
                    )
                {
                    return Err(rejected("receipt relay display predecessor"));
                }
                if !self.restricted {
                    delivery_relay_clock(
                        presentation.review_ceiling_ms,
                        presentation.facts.reviewed_at_ms,
                        presentation.facts.expires_at_ms,
                        pair,
                        self.clocks,
                        &mut s.pair.last_wall,
                    )?;
                }
                s.delivery.prepare_read.wire = Some(presentation.clone());
                s.delivery.prepare_read.phase = 144;
                Ok(!self.restricted)
            }
            Packet::V3Prepared { data, .. } => {
                data.validate()?;
                let slot = &mut s.delivery.prepare_read;
                let p = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("receipt relay result before display"))?;
                if slot.reported || slot.phase != 145 || !prepared_matches(data, p) {
                    return Err(rejected("receipt relay result mismatch/replay"));
                }
                slot.prepared = Some(data.clone());
                slot.reported = true;
                slot.phase = 146;
                Ok(true)
            }
            Packet::V3ReceiveDisplay { presentation } => {
                presentation.validate()?;
                if s.delivery.receive.wire.is_some()
                    || !receive_matches(
                        presentation,
                        &entry.presentation,
                        pair,
                        result,
                        &current,
                        export,
                        s.delivery.owner_selection.as_ref(),
                        s.delivery.prepare_read.wire.as_ref(),
                        s.delivery.prepare_read.prepared.as_ref(),
                    )
                    || !s.delivery.prepare_read.reported
                {
                    return Err(rejected("receipt relay display predecessor"));
                }
                if !self.restricted {
                    delivery_relay_clock(
                        presentation.review_ceiling_ms,
                        presentation.facts.reviewed_at_ms,
                        presentation.facts.expires_at_ms,
                        pair,
                        self.clocks,
                        &mut s.pair.last_wall,
                    )?;
                }
                s.delivery.receive.wire = Some(presentation.clone());
                s.delivery.receive.phase = 147;
                Ok(!self.restricted)
            }
            Packet::V3Received { data, .. } => {
                data.validate()?;
                let slot = &mut s.delivery.receive;
                let p = slot
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("receipt relay result before display"))?;
                if slot.reported || slot.phase != 148 || !received_matches(data, p) {
                    return Err(rejected("receipt relay result mismatch/replay"));
                }
                slot.result = Some(data.clone());
                slot.reported = true;
                slot.phase = 149;
                Ok(true)
            }
            _ => Err(rejected("wrong delivery relay event")),
        }
    }
}
fn delivery_relay_clock(
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
        return Err(rejected("delivery original relay window"));
    }
    *last = wall;
    Ok(())
}
fn prepared_matches(d: &SignerV3PreparedV1, p: &SignerV3PrepareReadPresentationV1) -> bool {
    d.validate().is_ok()
        && d.prepare_read_presentation_digest == p.presentation_digest
        && d.read_session_digest == p.presentation_digest
        && d.source_identity_digest == p.facts.source_identity_digest
        && d.preparation_digest == p.facts.preparation_digest
}
fn received_matches(d: &SignerV3ReceivedV1, p: &SignerV3ReceivePresentationV1) -> bool {
    d.validate().is_ok()
        && d.receive_presentation_digest == p.presentation_digest
        && d.prepare_read_presentation_digest == p.facts.prepare_read_presentation_digest
        && d.source_identity_digest == p.facts.source_identity_digest
        && d.owner_service_digest == p.facts.owner_service_digest
        && d.payload_digest == p.facts.payload_digest
        && d.payload_bytes == p.facts.payload_bytes
        && d.fixed_identity_digest == p.facts.fixed_identity_digest
}

/// Restriction-only retained custody. It cannot authorize any history or payload operation.
pub struct SignerV3PreparedLifetimeV1 {
    binding: Arc<PrepareReadBinding>,
}
impl SignerV3PreparedLifetimeV1 {
    pub fn check_current(&self) -> Result<()> {
        self.binding.custody_bounds()?;
        self.binding.pair.entry.core.check_action_restrictions()
    }
    pub fn prepare_read_presentation_digest(&self) -> &str {
        &self.binding.p.presentation_digest
    }
    pub fn read_presentation_digest(&self) -> &str {
        self.prepare_read_presentation_digest()
    }
    pub fn source_identity_digest(&self) -> &str {
        &self.binding.p.facts.source_identity_digest
    }
    pub fn original_service_deadline(&self) -> Instant {
        self.binding.service_deadline
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.pair.entry.original_source
    }
    pub fn original_channel_deadline(&self) -> Instant {
        self.binding.pair.channel_deadline
    }
    pub fn original_material_deadline(&self) -> Instant {
        self.binding.material_deadline
    }
}
#[derive(Clone)]
struct OwnerSelection {
    json: String,
    challenge: String,
    source: String,
    export: String,
}

impl CoordinatorFinancialEndpointV1 {
    /// Ordinary public configuration selection only. The later Read needs a
    /// separate native ticket and commits these exact bytes and nonce.
    pub fn try_select_v3_owner_setup(
        &mut self,
        role: Target,
        owner_setup_json: String,
    ) -> Result<FinancialSendProgressV1> {
        SignerV3OwnerSetupSelectionV1::parse_json(&owner_setup_json)?;
        let i = role.index();
        let s = &mut self.v3_entries[i];
        let pair = s
            .pair
            .binding
            .as_ref()
            .ok_or_else(|| rejected("owner selection before Pair"))?;
        pair.channel_bounds()?;
        let export = s.redisclosure.actual_export()?;
        if s.delivery.owner_selection.is_some() || self.core.phase.phase(i) != 143 {
            return Err(rejected("owner selection reordered or duplicate"));
        }
        let selected = OwnerSelection {
            json: owner_setup_json,
            challenge: state::nonce()?,
            source: pair.p.facts.source_identity_digest.clone(),
            export: export.presentation_digest.clone(),
        };
        let packet = Packet::V3OwnerSelection {
            role,
            source_identity_digest: selected.source.clone(),
            redisclosure_presentation_digest: selected.export.clone(),
            owner_setup_json: selected.json.clone(),
            owner_selection_challenge: selected.challenge.clone(),
        };
        let deadline = pair.channel_deadline;
        s.delivery.owner_selection = Some(selected);
        if self.core.phase.source_send_restricted(i, 143)? {
            return Ok(FinancialSendProgressV1::Restricted);
        }
        let result = self.send_positive(&packet, deadline);
        if result.is_err() {
            self.core.phase.revoke();
        }
        result
    }
}
impl SignerFinancialWorkflowOriginV1 {
    pub(in crate::financial_workflow_origin) fn receive_v3_owner_selection(
        &mut self,
        p: Packet,
    ) -> Result<SignerFinancialWorkflowRequestV1> {
        let Packet::V3OwnerSelection {
            role,
            source_identity_digest,
            redisclosure_presentation_digest,
            owner_setup_json,
            owner_selection_challenge,
        } = p
        else {
            return Err(rejected("wrong owner selection"));
        };
        SignerV3OwnerSetupSelectionV1::parse_json(&owner_setup_json)?;
        self.core.check_action_restrictions()?;
        let s = &mut self.v3_entry;
        let pair = s
            .pair
            .binding
            .as_ref()
            .ok_or_else(|| rejected("owner selection before Pair"))?;
        pair.channel_bounds()?;
        let export = s.redisclosure.actual_export()?;
        if role != self.target
            || self.core.phase.phase(role.index()) != 143
            || s.delivery.owner_selection.is_some()
            || source_identity_digest != pair.p.facts.source_identity_digest
            || redisclosure_presentation_digest != export.presentation_digest
            || !state::hash(&owner_selection_challenge)
        {
            return Err(rejected("owner selection original predecessor"));
        }
        s.delivery.owner_selection = Some(OwnerSelection {
            json: owner_setup_json.clone(),
            challenge: owner_selection_challenge.clone(),
            source: source_identity_digest,
            export: redisclosure_presentation_digest,
        });
        Ok(SignerFinancialWorkflowRequestV1::V3OwnerSelection {
            owner_setup_json,
            owner_selection_challenge,
        })
    }
}
impl HostFinancialWorkflowRelayV1 {
    pub(in crate::financial_workflow_origin) fn down_v3_owner_selection(
        &mut self,
        p: &Packet,
    ) -> Result<()> {
        let Packet::V3OwnerSelection {
            role,
            source_identity_digest,
            redisclosure_presentation_digest,
            owner_setup_json,
            owner_selection_challenge,
        } = p
        else {
            return Err(rejected("wrong owner selection relay"));
        };
        SignerV3OwnerSetupSelectionV1::parse_json(owner_setup_json)?;
        if self.restricted {
            return Err(rejected("owner selection after R"));
        }
        let s = &mut self.v3_entries[role.index()];
        let pair = s
            .pair
            .wire
            .as_ref()
            .ok_or_else(|| rejected("owner selection relay before Pair"))?;
        let export = s.redisclosure.actual_export()?;
        if s.delivery.owner_selection.is_some()
            || s.delivery.prepare_read.wire.is_some()
            || source_identity_digest != &pair.facts.source_identity_digest
            || redisclosure_presentation_digest != &export.presentation_digest
            || !state::hash(owner_selection_challenge)
        {
            return Err(rejected("owner selection relay predecessor"));
        }
        delivery_relay_clock(
            pair.channel_ceiling_ms,
            pair.facts.reviewed_at_ms,
            pair.facts.channel_expires_at_ms,
            pair,
            self.clocks,
            &mut s.pair.last_wall,
        )?;
        s.delivery.owner_selection = Some(OwnerSelection {
            json: owner_setup_json.clone(),
            challenge: owner_selection_challenge.clone(),
            source: source_identity_digest.clone(),
            export: redisclosure_presentation_digest.clone(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_local_client_result_is_exact_preparation_not_remote_serving() {
        let r = crate::signer_v3_delivery_data::tests::read();
        let mut d = crate::signer_v3_delivery_data::tests::prepared();
        assert!(prepared_matches(&d, &r));
        d.preparation_digest = "ff".repeat(32);
        assert!(!prepared_matches(&d, &r));
    }
    #[test]
    fn verified_receive_observation_binds_final_and_exact_payload() {
        let p = crate::signer_v3_delivery_data::tests::receive();
        let mut d = SignerV3ReceivedV1 {
            receive_presentation_digest: p.presentation_digest.clone(),
            prepare_read_presentation_digest: p.facts.prepare_read_presentation_digest.clone(),
            source_identity_digest: p.facts.source_identity_digest.clone(),
            owner_service_digest: p.facts.owner_service_digest.clone(),
            recipient_intent_digest: "ee".repeat(32),
            payload_digest: p.facts.payload_digest.clone(),
            payload_bytes: p.facts.payload_bytes,
            fixed_identity_digest: p.facts.fixed_identity_digest.clone(),
        };
        assert!(received_matches(&d, &p));
        d.payload_bytes += 1;
        assert!(!received_matches(&d, &p));
        d.payload_bytes -= 1;
        d.receive_presentation_digest = "ff".repeat(32);
        assert!(!received_matches(&d, &p));
    }
    #[test]
    fn initial_read_and_receive_never_set_completed_v3() {
        let p = state::Phases::new();
        p.step(0, 0, 143).unwrap();
        for (a, b) in [
            (143, 144),
            (144, 145),
            (145, 146),
            (146, 147),
            (147, 148),
            (148, 149),
        ] {
            p.step(0, a, b).unwrap();
        }
        assert_ne!(p.phase(0), V3_HELD);
        p.revoke();
        assert!(p.step(0, 149, 150).is_err());
    }
}
