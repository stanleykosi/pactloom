//! Actual C-only initial-history tickets. Data never constructs Serving; only
//! an authenticated original fixed W acknowledgment does. No late-R read output.
use super::*;
use crate::financial_history_channel::{Packet as HP, Setup};
use crate::financial_history_data::{
    FinancialHistoryInputsV1, FinancialHistoryPresentationV1, FinancialHistoryReadBindingV1,
};
use std::sync::atomic::AtomicU64;
pub(super) const H_SETUP_REVIEW: u8 = 1;
pub(super) const H_SETUP_ADMITTED: u8 = 2;
pub(super) const H_REVIEW: u8 = 3;
pub(super) const H_SERVING: u8 = 4;
pub(super) const H_DONE: u8 = 5;
pub(super) const H_RETIRED:u8=6;
struct SetupReview {
    read: Arc<ReadReviewed>,
    wire: Setup,
    ceiling: Instant,
}
impl SetupReview {
    fn core(&self) -> &Arc<Core> {
        &self.read.entry.core
    }
    fn slot(&self) -> usize {
        self.read.entry.slot()
    }
    fn check_bounds(&self)->Result<()>{self.read.check_bounds()?;crate::channel::require_time(self.ceiling)}
    fn check(&self)->Result<()>{self.check_bounds()?;self.core().check_action_restrictions()}
}
struct HReview {
    setup: Arc<SetupReview>,
    data: FinancialHistoryPresentationV1,
    instance: String,
    challenge: String,
    ceiling: Instant,
    last_wall: AtomicU64,
}
impl HReview {
    fn core(&self) -> &Arc<Core> {
        self.setup.core()
    }
    fn slot(&self) -> usize {
        self.setup.slot()
    }
    fn check(&self) -> Result<()> {
        self.check_bounds()?;
        self.core().check_action_restrictions()
    }
    fn check_bounds(&self) -> Result<()> {
        self.setup.read.check_bounds()?;
        crate::channel::require_time(self.ceiling)?;
        let wall = state::wall_ms()?;
        let old = self.last_wall.fetch_max(wall, Ordering::AcqRel);
        if wall < old || wall < self.data.prepared_at_ms || wall >= self.data.expires_at_ms {
            return Err(rejected("initial history native source clock"));
        }
        Ok(())
    }
}
pub struct FinancialHistorySetupTicketV1 {
    binding: Arc<SetupReview>,
    consumed: bool,
}
impl FinancialHistorySetupTicketV1 {
    pub fn inputs(&self) -> &FinancialHistoryInputsV1 {
        &self.binding.wire.inputs
    }
    pub fn read_binding(&self) -> &FinancialHistoryReadBindingV1 {
        &self.binding.wire.read_binding
    }
    pub fn native_deadline(&self) -> Instant {
        self.binding.ceiling
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.check()?;
        if self.binding.core().phase.history_phase(self.binding.slot()) != H_SETUP_REVIEW {
            return Err(rejected("initial history Setup consumed"));
        }
        Ok(())
    }
}
impl Drop for FinancialHistorySetupTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct FinancialHistorySetupOutboundV1 {
    binding: Arc<SetupReview>,
    consumed: bool,
}
impl Drop for FinancialHistorySetupOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct FinancialHistoryReviewTicketV1 {
    binding: Arc<HReview>,
    consumed: bool,
}
impl FinancialHistoryReviewTicketV1 {
    pub fn presentation(&self) -> &FinancialHistoryPresentationV1 {
        &self.binding.data
    }
    pub fn native_deadline(&self) -> Instant {
        self.binding.ceiling
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.check()?;
        if self.binding.core().phase.history_phase(self.binding.slot()) != H_REVIEW {
            return Err(rejected("initial history review consumed"));
        }
        Ok(())
    }
}
impl Drop for FinancialHistoryReviewTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct FinancialHistoryServeOutboundV1 {
    binding: Arc<HReview>,
    consumed: bool,
}
impl Drop for FinancialHistoryServeOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
/// A check-only prerequisite, NOT the S Read grant. The actual original fixed W
/// acknowledged the independently approved owner-only service before this exists.
pub struct FinancialHistoryServingV1 {
    binding: Arc<HReview>,
}
impl FinancialHistoryServingV1 {
    pub fn presentation(&self) -> &FinancialHistoryPresentationV1 {
        &self.binding.data
    }
    pub fn native_deadline(&self) -> Instant {
        self.binding.ceiling
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.check()?;
        if self.binding.core().phase.history_phase(self.binding.slot()) != H_SERVING {
            return Err(rejected("initial history no longer Serving"));
        }
        Ok(())
    }
    pub(super) fn retain(&self) -> Result<HistoryServiceLease> {
        self.check_current()?;
        Ok(HistoryServiceLease {
            binding: Arc::clone(&self.binding),
        })
    }
    pub(in crate::financial_workflow_origin) fn matches_read(
        &self,
        core: &Arc<Core>,
        read: &Arc<ReadReviewed>,
    ) -> Result<()> {
        self.check_current()?;
        if !Arc::ptr_eq(core, self.binding.core())
            || !Arc::ptr_eq(read, &self.binding.setup.read)
            || self.binding.data.read_binding.read != read.wire
            || self.binding.ceiling > read.ceiling
        {
            return Err(rejected("initial Read and actual Serving mismatch"));
        }
        Ok(())
    }
}
/// Restriction-only retained service observation inside the actual S Read
/// outbound. No importer or independent source/Read permission exists.
pub(crate) struct HistoryServiceLease {
    binding: Arc<HReview>,
}
impl HistoryServiceLease {
    pub(crate) fn check_bounds(&self)->Result<()>{
        self.binding.check_bounds()?;
        if self.binding.core().phase.history_phase(self.binding.slot())!=H_SERVING{return Err(rejected("initial Read service no longer Serving"));}Ok(())
    }
    pub(crate) fn deadline(&self)->Instant{self.binding.ceiling}
    pub(crate) fn check(&self) -> Result<()> {
        self.binding.check()?;
        if self.binding.core().phase.history_phase(self.binding.slot()) != H_SERVING {
            return Err(rejected(
                "initial history outbound service no longer Serving",
            ));
        }
        Ok(())
    }
}
pub enum CoordinatorFinancialHistoryEventV1 {
    Display(FinancialHistoryReviewTicketV1),
    Serving(FinancialHistoryServingV1),
    PreparationFailed(Target),
    ServiceFailed(Target),
    Disposed(Target),
    PurposeClosed(Target),
    Restricted(Target),
}
#[derive(Default)]
pub(super) struct CHSlot {
    setup: Option<Arc<SetupReview>>,
    display: Option<FinancialHistoryPresentationV1>,
    identity: Option<(String, String)>,
    review: Option<Arc<HReview>>,
    wire_phase: u8,
    serving_ack: bool,
    history_retained: bool,
    finish_sent: bool,
    failed: bool,
    cancel_sent: bool,
    disposed: bool,
    close_sent: bool,
    closed: bool,
    cleanup: Option<Instant>,
    retired:bool,
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_history_setup(
        &self,
        mut ticket: FinancialHistorySetupTicketV1,
    ) -> Result<FinancialHistorySetupOutboundV1> {
        if !Arc::ptr_eq(&self.core, ticket.binding.core()) {
            self.revoke();
            return Err(rejected("foreign initial history Setup"));
        }
        ticket.check_current()?;
        self.core
            .phase
            .history_step(ticket.binding.slot(), H_SETUP_REVIEW, H_SETUP_ADMITTED)?;
        ticket.consumed = true;
        Ok(FinancialHistorySetupOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            consumed: false,
        })
    }
    /// Separate focused native Serve gesture after complete authenticated review.
    pub fn admit_history_serve(
        &self,
        mut ticket: FinancialHistoryReviewTicketV1,
    ) -> Result<FinancialHistoryServeOutboundV1> {
        if !Arc::ptr_eq(&self.core, ticket.binding.core()) {
            self.revoke();
            return Err(rejected("foreign initial history review"));
        }
        ticket.check_current()?;
        self.core
            .phase
            .history_step(ticket.binding.slot(), H_REVIEW, H_SERVING)?;
        ticket.consumed = true;
        Ok(FinancialHistoryServeOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    /// Ordinary preselected paths bind only to the actual pending S Read. No
    /// protected reads/listener activity occurs until a native Setup is consumed.
    pub fn prepare_history_setup(&mut self,role:Target,inputs:FinancialHistoryInputsV1,original_native_ceiling:Instant)->Result<FinancialHistorySetupTicketV1>{
        self.try_prepare_history_setup(role,inputs,original_native_ceiling)?.ok_or_else(||rejected("history Setup preparation restricted"))
    }
    pub fn try_prepare_history_setup(
        &mut self,
        role: Target,
        inputs: FinancialHistoryInputsV1,
        original_native_ceiling: Instant,
    ) -> Result<Option<FinancialHistorySetupTicketV1>> {
        self.core.check()?;
        inputs.validate()?;
        let i = role.index();
        let s = self.slots[i]
            .as_ref()
            .ok_or_else(|| rejected("initial history before Signer"))?;
        if s.wire_phase != READ_REVIEW || self.histories[i].setup.is_some() {
            return Err(rejected(
                "initial history requires one pending original Read",
            ));
        }
        let read = s
            .read
            .as_ref()
            .ok_or_else(|| rejected("initial history original Read missing"))?;
        read.check_bounds()?;
        let now = Instant::now();
        let ceiling = original_native_ceiling.min(read.ceiling);
        crate::channel::require_time(ceiling)?;
        if ceiling.duration_since(now) > std::time::Duration::from_secs(120) {
            return Err(rejected("initial history Setup ceiling too wide"));
        }
        let wire = Setup {
            inputs,
            read_binding: FinancialHistoryReadBindingV1 {
                read: read.wire.clone(),
            },
            setup_challenge: state::nonce()?,
            setup_ceiling_ms: self
                .clocks
                .restrictive_offset(ceiling, read.original_read)?,
        };
        wire.validate()?;
        let b = Arc::new(SetupReview {
            read: Arc::clone(read),
            wire,
            ceiling,
        });
        b.check_bounds()?;
        if let Err(error)=self.core.phase.history_step(i,0,H_SETUP_REVIEW){
            if self.core.phase.history_send_restricted(i,0)?{return Ok(None);}return Err(error);
        }
        self.histories[i].setup = Some(Arc::clone(&b));
        self.histories[i].wire_phase = H_SETUP_REVIEW;
        Ok(Some(FinancialHistorySetupTicketV1 {
            binding: b,
            consumed: false,
        }))
    }
    fn send_history_positive(&self,role:Target,packet:&HP,deadline:Instant)->Result<FinancialSendProgressV1>{
        self.transport_check()?;
        if let Some(c)=self.histories[role.index()].cleanup{crate::channel::require_time(c)?;}
        self.tree.as_ref().ok_or_else(||rejected("positive history tree consumed"))?.financial_history(role)?.financial_history_send_positive(packet,&self.core.phase,deadline)
    }
    fn send_history(&self, role: Target, packet: &HP) -> Result<()> {
        self.transport_check()?;
        if let Some(c) = self.histories[role.index()].cleanup {
            crate::channel::require_time(c)?;
        }
        self.tree
            .as_ref()
            .ok_or_else(|| rejected("initial history tree consumed"))?
            .financial_history(role)?
            .financial_history_send(packet)
    }
    pub fn send_history_setup(&mut self,outbound:FinancialHistorySetupOutboundV1)->Result<()>{self.try_send_history_setup(outbound)?.require_sent()}
    pub fn try_send_history_setup(
        &mut self,
        mut outbound: FinancialHistorySetupOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = &outbound.binding;
        let i = b.slot();
        if !Arc::ptr_eq(&self.core, b.core()) {
            return Err(rejected("foreign initial history Setup outbound"));
        }
        b.check_bounds()?;
        if self.histories[i].wire_phase != H_SETUP_REVIEW
            || self.core.phase.history_phase(i) != H_SETUP_ADMITTED
        {
            return Err(rejected("initial history Setup send phase"));
        }
        if self.core.phase.history_send_restricted(i,H_SETUP_ADMITTED)?{outbound.consumed=true;return Ok(FinancialSendProgressV1::Restricted);}
        outbound.consumed = true;
        let progress=self.send_history_positive(
            b.wire.read_binding.read.actor.signer_role,
            &HP::PrepareOnce {
                setup: b.wire.clone(),
            },b.ceiling)?;
        if progress==FinancialSendProgressV1::Sent{self.histories[i].wire_phase = H_SETUP_ADMITTED;}Ok(progress)
    }
    pub fn send_history_serve(&mut self,outbound:FinancialHistoryServeOutboundV1)->Result<()>{self.try_send_history_serve(outbound)?.require_sent()}
    pub fn try_send_history_serve(
        &mut self,
        mut outbound: FinancialHistoryServeOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = &outbound.binding;
        let i = b.slot();
        if !Arc::ptr_eq(&self.core, b.core()) {
            return Err(rejected("foreign initial history Serve outbound"));
        }
        b.check_bounds()?;
        if self.histories[i].wire_phase != H_REVIEW || self.core.phase.history_phase(i) != H_SERVING
        {
            return Err(rejected("initial history Serve send phase"));
        }
        if self.core.phase.history_send_restricted(i,H_SERVING)?{outbound.consumed=true;return Ok(FinancialSendProgressV1::Restricted);}
        outbound.consumed = true;
        let progress=self.send_history_positive(
            b.data.read_binding.read.actor.signer_role,
            &HP::Serve {
                setup_challenge: b.setup.wire.setup_challenge.clone(),
                witness_instance: b.instance.clone(),
                serve_challenge: b.challenge.clone(),
                presentation_digest: b.data.presentation_digest.clone(),
            },b.ceiling)?;
        if progress==FinancialSendProgressV1::Sent{self.histories[i].wire_phase = H_SERVING;}Ok(progress)
    }
    /// PRIVATE receive hook: call only from exact authenticated S HistoryRetained
    /// receive, never from a UI event or reconstructed ordinary completion data.
    pub(super) fn note_history_retained(
        &mut self,
        role: Target,
        read: &Arc<ReadReviewed>,
    ) -> Result<()> {
        let slot = &mut self.histories[role.index()];
        let setup = slot
            .setup
            .as_ref()
            .ok_or_else(|| rejected("history retained without actual W Setup"))?;
        if !Arc::ptr_eq(read, &setup.read)
            || !slot.serving_ack
            || slot.history_retained
            || slot.wire_phase != H_SERVING
        {
            return Err(rejected(
                "history retained without matching actual W service",
            ));
        }
        slot.history_retained = true;
        Ok(())
    }
    /// Restrictive completion only, after the actual original Signer has retained
    /// the complete history AND its one immutable Continue preparation.
    pub fn finish_history_read(&mut self,role:Target)->Result<()>{self.try_finish_history_read(role)?.require_sent()}
    pub fn try_finish_history_read(&mut self,role:Target)->Result<FinancialSendProgressV1>{
        self.core.check()?;let i=role.index();let slot=&self.histories[i];
        if !slot.history_retained||!slot.serving_ack||slot.finish_sent||slot.failed||slot.cancel_sent||slot.disposed||slot.wire_phase!=H_SERVING{
            return Err(rejected("initial history Finish without authenticated retention"));
        }
        let b=slot.review.as_ref().ok_or_else(||rejected("initial history Finish review missing"))?;
        // Completed Read's short clock is not renewed or used as permission.
        // This only stops its actual already-retained service.
        b.setup.read.entry.check_custody()?;
        if self.core.phase.history_send_restricted(i,H_SERVING)?{return Ok(FinancialSendProgressV1::Restricted);}
        let packet=HP::FinishRead{setup_challenge:b.setup.wire.setup_challenge.clone(),witness_instance:b.instance.clone(),
            presentation_digest:b.data.presentation_digest.clone(),read_presentation_digest:b.setup.read.wire.presentation_digest.clone()};
        let deadline=b.setup.read.entry.original_source.min(self.clocks.supervision());
        if let Err(error)=self.core.phase.history_step(i,H_SERVING,H_DONE){
            if self.core.phase.history_send_restricted(i,H_SERVING)?{return Ok(FinancialSendProgressV1::Restricted);}return Err(error);
        }
        let progress=self.send_history_positive(role,&packet,deadline)?;
        if progress==FinancialSendProgressV1::Sent{self.histories[i].finish_sent=true;self.histories[i].wire_phase=H_DONE;}Ok(progress)
    }
    pub fn try_receive_history(&mut self) -> Result<Option<CoordinatorFinancialHistoryEventV1>> {
        let result = self.receive_history_inner();
        if result.is_err() {
            self.core.close();
        }
        result
    }
    fn receive_history_inner(&mut self) -> Result<Option<CoordinatorFinancialHistoryEventV1>> {
        self.transport_check()?;
        for role in [Target::Signer1, Target::Signer2] {
            let i = role.index();
            if self.histories[i].closed {
                continue;
            }
            let Some(packet) = self
                .tree
                .as_ref()
                .ok_or_else(|| rejected("initial history tree consumed"))?
                .financial_history(role)?
                .financial_history_receive()?
            else {
                continue;
            };
            let slot = &mut self.histories[i];
            if let Some(c) = slot.cleanup {
                crate::channel::require_time(c)?;
            }
            let event = match packet {
                HP::Display {
                    setup_challenge,
                    witness_instance,
                    serve_challenge,
                    read_ceiling_ms,
                    data,
                } => {
                    data.validate()?;
                    let setup = slot
                        .setup
                        .as_ref()
                        .ok_or_else(|| rejected("unsolicited initial history Display"))?;
                    if slot.wire_phase != H_SETUP_ADMITTED
                        || slot.display.is_some()
                        || setup_challenge != setup.wire.setup_challenge
                        || data.read_binding != setup.wire.read_binding
                        || read_ceiling_ms != setup.read.wire.read_ceiling_ms
                        || data.network_profile_id != setup.wire.inputs.network_profile_id
                        || !state::hash(&witness_instance)
                        || !state::hash(&serve_challenge)
                    {
                        return Err(rejected("initial history Display binding"));
                    }
                    slot.wire_phase = H_REVIEW;
                    slot.display = Some(data.clone());
                    slot.identity = Some((witness_instance.clone(), serve_challenge.clone()));
                    let now = Instant::now();
                    let wall = state::wall_ms()?;
                    let ceiling = setup.read.ceiling.min(wall_ceiling(
                        now,
                        wall,
                        data.prepared_at_ms,
                        data.expires_at_ms,
                    )?);
                    let b = Arc::new(HReview {
                        setup: Arc::clone(setup),
                        data,
                        instance: witness_instance,
                        challenge: serve_challenge,
                        ceiling,
                        last_wall: AtomicU64::new(wall),
                    });
                    slot.review = Some(Arc::clone(&b));
                    // Validate all original clocks/source BEFORE classifying only
                    // the exact expected-phase R race as a restricted receive.
                    b.check_bounds()?;
                    if !received_history_progress(&self.core.phase, i, H_SETUP_ADMITTED, H_REVIEW)?
                    {
                        CoordinatorFinancialHistoryEventV1::Restricted(role)
                    } else {
                        CoordinatorFinancialHistoryEventV1::Display(
                            FinancialHistoryReviewTicketV1 {
                                binding: b,
                                consumed: false,
                            },
                        )
                    }
                }
                HP::Serving {
                    setup_challenge,
                    witness_instance,
                    serve_challenge,
                    presentation_digest,
                } => {
                    let b = slot
                        .review
                        .as_ref()
                        .ok_or_else(|| rejected("initial history Serving before review"))?;
                    if slot.wire_phase != H_SERVING
                        || slot.serving_ack
                        || setup_challenge != b.setup.wire.setup_challenge
                        || witness_instance != b.instance
                        || serve_challenge != b.challenge
                        || presentation_digest != b.data.presentation_digest
                    {
                        return Err(rejected("initial history Serving binding"));
                    }
                    slot.serving_ack = true;
                    b.check_bounds()?;
                    if self.core.phase.history_send_restricted(i,H_SERVING)? {
                        CoordinatorFinancialHistoryEventV1::Restricted(role)
                    } else {
                        CoordinatorFinancialHistoryEventV1::Serving(FinancialHistoryServingV1 {
                            binding: Arc::clone(b),
                        })
                    }
                }
                HP::PreparationFailed { setup_challenge } => {
                    if slot.failed
                        || slot.display.is_some()
                        || slot
                            .setup
                            .as_ref()
                            .is_none_or(|b| b.wire.setup_challenge != setup_challenge)
                    {
                        return Err(rejected("initial history preparation failure binding"));
                    }
                    slot.failed = true;
                    self.core.phase.revoke();
                    CoordinatorFinancialHistoryEventV1::PreparationFailed(role)
                }
                HP::ServiceFailed {
                    setup_challenge,
                    witness_instance,
                    presentation_digest,
                } => {
                    let setup = slot
                        .setup
                        .as_ref()
                        .ok_or_else(|| rejected("initial history failure before Setup"))?;
                    let data = slot
                        .display
                        .as_ref()
                        .ok_or_else(|| rejected("initial history failure before Display"))?;
                    if slot.failed
                        || slot.disposed
                        || setup_challenge != setup.wire.setup_challenge
                        || slot
                            .identity
                            .as_ref()
                            .is_none_or(|(w, _)| w != &witness_instance)
                        || presentation_digest != data.presentation_digest
                    {
                        return Err(rejected("initial history service failure binding"));
                    }
                    slot.failed = true;
                    self.core.phase.revoke();
                    CoordinatorFinancialHistoryEventV1::ServiceFailed(role)
                }
                HP::Disposed {
                    coordinator,
                    session,
                    cleanup_ceiling_ms,
                } => {
                    if coordinator != self.coordinator
                        || session != self.session
                        || slot.disposed
                        || (!slot.finish_sent && !slot.cancel_sent && !slot.failed)
                    {
                        return Err(rejected("initial history disposal binding"));
                    }
                    let original = self
                        .clocks
                        .received_cleanup(cleanup_ceiling_ms, Instant::now())?;
                    slot.cleanup = Some(self.clocks.retain_cleanup(
                        slot.cleanup,
                        original,
                        Instant::now(),
                    )?);
                    slot.disposed = true;
                    CoordinatorFinancialHistoryEventV1::Disposed(role)
                }
                HP::PurposeClosed {
                    coordinator,
                    session,
                } => {
                    if coordinator != self.coordinator
                        || session != self.session
                        || !slot.disposed
                        || !slot.close_sent
                        || slot.closed
                    {
                        return Err(rejected("initial history close binding"));
                    }
                    slot.closed = true;
                    CoordinatorFinancialHistoryEventV1::PurposeClosed(role)
                }
                _ => return Err(rejected("unexpected initial history observation")),
            };
            return Ok(Some(event));
        }
        Ok(None)
    }
    pub fn close_history_purpose(&mut self, role: Target) -> Result<()> {
        let slot = &mut self.histories[role.index()];
        if !slot.disposed || slot.close_sent {
            return Err(rejected("initial history close before disposal"));
        }
        let original = slot
            .cleanup
            .ok_or_else(|| rejected("initial history disposal cutoff missing"))?;
        slot.cleanup = Some(
            self.clocks
                .retain_cleanup(slot.cleanup, original, Instant::now())?,
        );
        slot.close_sent = true;
        self.send_history(
            role,
            &HP::ClosePurpose {
                coordinator: self.coordinator.clone(),
                session: self.session.clone(),
            },
        )
    }
    pub(super) fn cancel_histories(&mut self) -> Result<()> {
        for role in [Target::Signer1, Target::Signer2] {
            let slot = &mut self.histories[role.index()];
            if slot.closed || slot.cancel_sent {
                continue;
            }
            slot.cancel_sent = true;
            self.send_history(
                role,
                &HP::Cancel {
                    coordinator: self.coordinator.clone(),
                    session: self.session.clone(),
                },
            )?;
        }
        Ok(())
    }
}
fn received_history_progress(phase:&Phases,slot:usize,from:u8,to:u8)->Result<bool>{
    if phase.history_send_restricted(slot,from)?{return Ok(false);}
    match phase.history_step(slot,from,to){
        Ok(())=>Ok(!phase.history_send_restricted(slot,to)?),
        Err(error)=>{if phase.history_send_restricted(slot,from)?{Ok(false)}else{Err(error)}}
    }
}
impl CHSlot {
    pub(super) fn retirement_completed(&self)->bool{self.retired}
    pub(super) fn retirement_idle(&self,target:bool)->bool{
        self.setup.is_none()||self.retired||(target&&self.history_retained&&self.finish_sent&&self.disposed&&!self.failed&&!self.cancel_sent)
    }
    pub(super) fn retirement_record(&self,read:&Arc<ReadReviewed>)->Result<(&str,Instant)>{
        let b=self.review.as_ref().ok_or_else(||rejected("History retirement before actual service"))?;
        if !self.history_retained||!self.finish_sent||!self.disposed||self.failed||self.cancel_sent||self.close_sent||self.retired
            ||self.wire_phase!=H_DONE||!Arc::ptr_eq(read,&b.setup.read)||b.data.read_binding.read!=read.wire {
            return Err(rejected("History retirement missing exact completed service custody"));
        }
        Ok((&b.instance,self.cleanup.ok_or_else(||rejected("History retirement original cleanup missing"))?))
    }
    pub(super) fn retirement_closed(&mut self)->Result<()>{
        if !self.disposed||!self.close_sent||self.closed{return Err(rejected("History retirement close reordered"));}self.closed=true;Ok(())
    }
    pub(super) fn retirement_reaped(&mut self)->Result<()>{
        if !self.closed||self.retired||self.wire_phase!=H_DONE{return Err(rejected("History retirement normal reap reordered"));}
        self.retired=true;self.wire_phase=H_RETIRED;Ok(())
    }

    pub(super) fn closed(&self) -> bool {
        self.closed
    }
    pub(super) fn observe_active(&self, core: &Core, i: usize) -> Result<()> {
        match core.phase.history_phase(i) {
            H_SETUP_REVIEW | H_SETUP_ADMITTED => self
                .setup
                .as_ref()
                .ok_or_else(|| rejected("active initial history Setup missing"))?
                .check(),
            H_REVIEW | H_SERVING if !self.history_retained => self
                .review
                .as_ref()
                .ok_or_else(|| rejected("active initial history review missing"))?
                .check(),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_receive_race_does_not_mask_wrong_phase_or_issue_progress() {
        let p = Phases::new();
        p.history_step(0, 0, H_SETUP_ADMITTED).unwrap();
        p.revoke();
        assert!(!received_history_progress(&p, 0, H_SETUP_ADMITTED, H_REVIEW).unwrap());
        assert_eq!(p.history_phase(0), H_SETUP_ADMITTED);
        assert!(received_history_progress(&p, 0, H_REVIEW, H_SERVING).is_err());
    }
    #[test]
    fn history_slots_share_restriction_without_aliasing_append_or_signer() {
        let p = Phases::new();
        p.history_step(0, 0, H_REVIEW).unwrap();
        p.history_step(1, 0, H_REVIEW).unwrap();
        assert_eq!(p.witness_phase(0), 0);
        assert_eq!(p.phase(0), 0);
        p.history_step(0, H_REVIEW, H_SERVING).unwrap();
        p.revoke();
        assert!(p.history_step(1, H_REVIEW, H_SERVING).is_err());
        assert_eq!(p.history_phase(0), H_SERVING);
        assert_eq!(p.history_phase(1), H_REVIEW);
    }
}

#[cfg(test)]mod positive_receive_snapshot_tests{
    use super::*;
    #[test]fn history_receive_q_and_wrong_phase_are_fatal_even_after_r(){
        let p=Phases::new();p.history_step(0,0,H_SETUP_ADMITTED).unwrap();p.begin_quiescence(p.snapshot()).unwrap();p.revoke();
        assert!(received_history_progress(&p,0,H_SETUP_ADMITTED,H_REVIEW).is_err());
        let p=Phases::new();p.history_step(0,0,H_SETUP_ADMITTED).unwrap();p.revoke();
        assert!(!received_history_progress(&p,0,H_SETUP_ADMITTED,H_REVIEW).unwrap());
        assert!(received_history_progress(&p,0,H_REVIEW,H_REVIEW).is_err());
    }
}
