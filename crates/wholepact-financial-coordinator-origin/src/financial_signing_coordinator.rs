//! Actual C-only original-signing tickets. Data never constructs Serving; only
//! an authenticated original fixed W acknowledgment does. No new I/O after R.
use super::*;
use crate::financial_signing_channel::{Packet as GP, Setup};
use crate::financial_signing_data::{
    FinancialSigningInputsV1, FinancialSigningPresentationV1, FinancialSigningOriginalV1, FinancialSigningServiceV1,
};
use std::sync::atomic::AtomicU64;
pub(super) const G_SETUP_REVIEW: u8 = 1;
pub(super) const G_SETUP_ADMITTED: u8 = 2;
pub(super) const G_REVIEW: u8 = 3;
pub(super) const G_SERVING: u8 = 4;
pub(super) const G_DONE: u8 = 5;
struct SetupReview {entry:Arc<EntryReviewed>,wire:Setup,ceiling:Instant}
impl SetupReview {
    fn core(&self)->&Arc<Core>{&self.entry.core}
    fn slot(&self)->usize{self.entry.slot()}
    fn check_bounds(&self)->Result<()>{self.entry.check_custody()?;crate::channel::require_time(self.ceiling)}
    fn check(&self)->Result<()>{self.check_bounds()?;self.core().check_action_restrictions()}
}
struct GReview {setup:Arc<SetupReview>,data:FinancialSigningPresentationV1,instance:String,challenge:String,
    service_ceiling_ms:u64,service_ceiling:Instant,review_ceiling:Instant,last_wall:AtomicU64}
impl GReview {
    fn core(&self)->&Arc<Core>{self.setup.core()}
    fn slot(&self)->usize{self.setup.slot()}
    fn service_bounds(&self)->Result<()>{self.setup.entry.check_custody()?;crate::channel::require_time(self.service_ceiling)?;
        let wall=state::wall_ms()?;let old=self.last_wall.fetch_max(wall,Ordering::AcqRel);
        if wall<old||wall<self.data.valid_from_ms||wall>=self.data.valid_until_ms{return Err(rejected("financial signing service wall clock"));}Ok(())}
    fn service_check(&self)->Result<()>{self.service_bounds()?;self.core().check_action_restrictions()}
    fn check_bounds(&self)->Result<()>{self.service_bounds()?;crate::channel::require_time(self.review_ceiling)?;
        if state::wall_ms()? >= self.data.expires_at_ms{return Err(rejected("financial signing Setup review clock"));}Ok(())}
    fn check(&self)->Result<()>{self.check_bounds()?;self.core().check_action_restrictions()}
    fn correlation(&self)->FinancialSigningServiceV1{FinancialSigningServiceV1{original:self.data.original.clone(),witness_instance:self.instance.clone(),
        presentation_digest:self.data.presentation_digest.clone(),service_challenge:self.challenge.clone(),service_ceiling_ms:self.service_ceiling_ms,
        writer_certificate_digest:self.data.writer_certificate_digest.clone(),admission_digest:self.data.admission_digest.clone()}}
}
pub struct FinancialSigningSetupTicketV1 {
    binding: Arc<SetupReview>,
    consumed: bool,
}
impl FinancialSigningSetupTicketV1 {
    pub fn inputs(&self) -> &FinancialSigningInputsV1 {
        &self.binding.wire.inputs
    }
    pub fn original_binding(&self) -> &FinancialSigningOriginalV1 {
        &self.binding.wire.original
    }
    pub fn native_deadline(&self) -> Instant {
        self.binding.ceiling
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.check()?;
        if self.binding.core().phase.signing_phase(self.binding.slot()) != G_SETUP_REVIEW {
            return Err(rejected("financial signing Setup consumed"));
        }
        Ok(())
    }
}
impl Drop for FinancialSigningSetupTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct FinancialSigningSetupOutboundV1 {
    binding: Arc<SetupReview>,
    consumed: bool,
}
impl Drop for FinancialSigningSetupOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct FinancialSigningReviewTicketV1 {
    binding: Arc<GReview>,
    consumed: bool,
}
impl FinancialSigningReviewTicketV1 {
    pub fn presentation(&self) -> &FinancialSigningPresentationV1 {
        &self.binding.data
    }
    pub fn native_deadline(&self) -> Instant {
        self.binding.review_ceiling
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.check()?;
        if self.binding.core().phase.signing_phase(self.binding.slot()) != G_REVIEW {
            return Err(rejected("financial signing review consumed"));
        }
        Ok(())
    }
}
impl Drop for FinancialSigningReviewTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct FinancialSigningServeOutboundV1 {
    binding: Arc<GReview>,
    consumed: bool,
}
impl Drop for FinancialSigningServeOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
/// Actual original W acknowledgment, not a grant for S or a data importer.
/// No constructor, Clone or serde; ordinary correlation cannot recreate this.
pub struct FinancialSigningServingV1 {binding:Arc<GReview>}
impl FinancialSigningServingV1 {
    pub fn presentation(&self)->&FinancialSigningPresentationV1{&self.binding.data}
    pub fn service_deadline(&self)->Instant{self.binding.service_ceiling}
    pub fn check_current(&self)->Result<()>{self.binding.service_check()?;
        if self.binding.core().phase.signing_phase(self.binding.slot())!=G_SERVING{return Err(rejected("financial signing service not current"));}Ok(())}
    pub(in crate::financial_workflow_origin) fn matches_writer_read(&self,core:&Arc<Core>,p:&crate::signer_writer_read_acquire_data::SignerFinancialWriterReadPresentationV1)->Result<()> {
        self.check_current()?;p.validate()?;let o=&self.binding.data.original;let f=&p.facts;
        if !Arc::ptr_eq(core,self.binding.core())||p.actor!=o.actor||p.source_ceiling_ms!=o.source_ceiling_ms
            ||f.source_identity_digest!=o.signer_source_identity_digest||f.terms_digest!=o.terms_digest
            ||f.continuation_request_json!=o.request_json||f.continuation_request_digest!=o.request_digest
            ||f.admit_presentation_digest!=o.admit_presentation_digest||f.admit_request_digest!=o.request_digest
            ||f.admitted_head_sequence!=o.admitted_head_sequence||f.admitted_head_digest!=o.admitted_head_digest
            ||f.original_host_process_instance!=o.original_host_process_instance||f.owner_certificate_digest!=o.owner_certificate_digest
            ||f.owner_disclosure_digest!=o.owner_disclosure_digest||f.writer_certificate_digest!=self.binding.data.writer_certificate_digest
            ||f.source_expires_at_ms!=o.source_expires_at_ms{return Err(rejected("Writer Read and actual Signing service differ"));}Ok(())
    }
    pub(in crate::financial_workflow_origin) fn matches_acquire(&self,core:&Arc<Core>,p:&crate::signer_writer_read_acquire_data::SignerAcquirePresentationV1)->Result<()> {
        self.check_current()?;p.validate()?;let o=&self.binding.data.original;let f=&p.facts;
        if !Arc::ptr_eq(core,self.binding.core())||p.actor!=o.actor||p.source_ceiling_ms!=o.source_ceiling_ms
            ||f.source_identity_digest!=o.signer_source_identity_digest||f.terms_digest!=o.terms_digest
            ||f.continuation_request_json!=o.request_json||f.continuation_request_digest!=o.request_digest
            ||f.admit_presentation_digest!=o.admit_presentation_digest||f.original_host_process_instance!=o.original_host_process_instance
            ||f.owner_certificate_digest!=o.owner_certificate_digest||f.owner_disclosure_digest!=o.owner_disclosure_digest
            ||f.writer_certificate_digest!=self.binding.data.writer_certificate_digest||f.source_expires_at_ms!=o.source_expires_at_ms {
            return Err(rejected("Acquire recipe and actual Signing service differ"));
        } Ok(())
    }
    // Private same-Core lease copied only into an actual already-issued outbound.
    // It grants nothing and never supplies another native A constructor.
    pub(in crate::financial_workflow_origin) fn retain(&self)->Result<SigningServiceLease>{self.check_current()?;Ok(SigningServiceLease{binding:Arc::clone(&self.binding)})}
}
pub(in crate::financial_workflow_origin) struct SigningServiceLease{binding:Arc<GReview>}
impl SigningServiceLease {
    pub(in crate::financial_workflow_origin) fn check_bounds(&self)->Result<()>{self.binding.service_bounds()?;
        if self.binding.core().phase.signing_phase(self.binding.slot())!=G_SERVING{return Err(rejected("Signing outbound service ended"));}Ok(())}
    pub(in crate::financial_workflow_origin) fn deadline(&self)->Instant{self.binding.service_ceiling}
    pub(in crate::financial_workflow_origin) fn check(&self)->Result<()>{self.binding.service_check()?;
        if self.binding.core().phase.signing_phase(self.binding.slot())!=G_SERVING{return Err(rejected("Signing outbound service ended"));}Ok(())}
    pub(in crate::financial_workflow_origin) fn correlation(&self)->FinancialSigningServiceV1{self.binding.correlation()}
}
pub enum CoordinatorFinancialSigningEventV1 {
    Display(FinancialSigningReviewTicketV1),
    Serving(FinancialSigningServingV1),
    PreparationFailed(Target),
    ServiceFailed(Target),
    Disposed(Target),
    PurposeClosed(Target),
    Restricted(Target),
}
#[derive(Default)]
pub(super) struct CGSlot {
    setup: Option<Arc<SetupReview>>,
    display: Option<FinancialSigningPresentationV1>,
    identity: Option<(String, String)>,
    review: Option<Arc<GReview>>,
    wire_phase: u8,
    serving_ack: bool,
    finish_sent: bool,
    failed: bool,
    cancel_sent: bool,
    disposed: bool,
    close_sent: bool,
    closed: bool,
    cleanup: Option<Instant>,
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_signing_setup(
        &self,
        mut ticket: FinancialSigningSetupTicketV1,
    ) -> Result<FinancialSigningSetupOutboundV1> {
        if !Arc::ptr_eq(&self.core, ticket.binding.core()) {
            self.revoke();
            return Err(rejected("foreign financial signing Setup"));
        }
        ticket.check_current()?;
        self.core
            .phase
            .signing_step(ticket.binding.slot(), G_SETUP_REVIEW, G_SETUP_ADMITTED)?;
        ticket.consumed = true;
        Ok(FinancialSigningSetupOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            consumed: false,
        })
    }
    /// Separate focused native Serve gesture after complete authenticated review.
    pub fn admit_signing_serve(
        &self,
        mut ticket: FinancialSigningReviewTicketV1,
    ) -> Result<FinancialSigningServeOutboundV1> {
        if !Arc::ptr_eq(&self.core, ticket.binding.core()) {
            self.revoke();
            return Err(rejected("foreign financial signing review"));
        }
        ticket.check_current()?;
        self.core
            .phase
            .signing_step(ticket.binding.slot(), G_REVIEW, G_SERVING)?;
        ticket.consumed = true;
        Ok(FinancialSigningServeOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    /// Paths are ordinary until the separate native Setup action. The original
    /// linkage comes only from this same slot's authenticated retained Admit.
    pub fn prepare_signing_setup(&mut self,role:Target,inputs:FinancialSigningInputsV1,original_native_ceiling:Instant)->Result<FinancialSigningSetupTicketV1>{
        self.try_prepare_signing_setup(role,inputs,original_native_ceiling)?.ok_or_else(||rejected("signing Setup preparation restricted"))
    }
    pub fn try_prepare_signing_setup(&mut self,role:Target,inputs:FinancialSigningInputsV1,original_native_ceiling:Instant)->Result<Option<FinancialSigningSetupTicketV1>>{
        self.core.check()?;inputs.validate()?;let i=role.index();
        let s=self.slots[i].as_ref().ok_or_else(||rejected("Signing setup before original Signer"))?;
        if (s.wire_phase!=admit::AWAITING_NEXT_READ&&!s.writer_acquire.signing_setup_pending(s.wire_phase))||self.signing_services[i].setup.is_some()
            ||!self.witnesses[i].retirement_completed(){return Err(rejected("Signing requires actual Admit and owned predecessor retirement"));}
        let entry=s.entry.as_ref().ok_or_else(||rejected("Signing original Entry missing"))?;entry.check_custody()?;
        let(p,c)=s.admission.retained_result()?;let f=&p.facts;
        let original=FinancialSigningOriginalV1{actor:p.actor.clone(),continue_presentation_digest:p.continue_presentation_digest.clone(),prepared_digest:p.prepared_digest.clone(),
            admit_presentation_digest:p.presentation_digest.clone(),admission_ready_digest:c.admission_ready_digest.clone(),signer_source_identity_digest:f.source_identity_digest.clone(),
            admission_terms_digest:f.admission_terms_digest.clone(),request_json:f.request_json.clone(),request_digest:f.request_digest.clone(),original_host_process_instance:f.original_host_process_instance.clone(),
            owner_certificate_digest:f.owner_certificate_digest.clone(),owner_disclosure_json:f.disclosure_json.clone(),owner_disclosure_digest:f.disclosure_digest.clone(),owner_selection_digest:p.owner_selection_digest.clone(),
            terms_digest:f.terms_digest.clone(),account_id:f.account_id.clone(),network_profile_id:f.network_profile_id.clone(),operation_id:f.operation_id.clone(),admitted_head_sequence:c.head_sequence,
            admitted_head_digest:c.head_digest.clone(),source_ceiling_ms:p.source_ceiling_ms,source_expires_at_ms:f.source_expires_at_ms};
        original.validate()?;let now=Instant::now();let ceiling=original_native_ceiling.min(entry.original_source).min(self.clocks.supervision());
        crate::channel::require_time(ceiling)?;
        if ceiling.duration_since(now)>std::time::Duration::from_secs(120){return Err(rejected("Signing Setup ceiling too wide"));}
        let wire=Setup{inputs,original,setup_challenge:state::nonce()?,setup_ceiling_ms:self.clocks.restrictive_offset(ceiling,entry.original_source)?};wire.validate()?;
        let b=Arc::new(SetupReview{entry:Arc::clone(entry),wire,ceiling});b.check_bounds()?;
        if let Err(error)=self.core.phase.signing_step(i,0,G_SETUP_REVIEW){
            if self.core.phase.signing_send_restricted(i,0)?{return Ok(None);}return Err(error);
        }self.signing_services[i].setup=Some(Arc::clone(&b));self.signing_services[i].wire_phase=G_SETUP_REVIEW;
        Ok(Some(FinancialSigningSetupTicketV1{binding:b,consumed:false}))
    }
    fn send_signing_positive(&self,role:Target,packet:&GP,deadline:Instant)->Result<FinancialSendProgressV1>{
        self.transport_check()?;
        if let Some(c)=self.signing_services[role.index()].cleanup{crate::channel::require_time(c)?;}
        self.tree.as_ref().ok_or_else(||rejected("positive signing tree consumed"))?.financial_signing(role)?.financial_signing_send_positive(packet,&self.core.phase,deadline)
    }
    fn send_signing(&self, role: Target, packet: &GP) -> Result<()> {
        self.transport_check()?;
        if let Some(c) = self.signing_services[role.index()].cleanup {
            crate::channel::require_time(c)?;
        }
        self.tree
            .as_ref()
            .ok_or_else(|| rejected("financial signing tree consumed"))?
            .financial_signing(role)?
            .financial_signing_send(packet)
    }
    pub fn send_signing_setup(&mut self,outbound:FinancialSigningSetupOutboundV1)->Result<()>{self.try_send_signing_setup(outbound)?.require_sent()}
    pub fn try_send_signing_setup(
        &mut self,
        mut outbound: FinancialSigningSetupOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = &outbound.binding;
        let i = b.slot();
        if !Arc::ptr_eq(&self.core, b.core()) {
            return Err(rejected("foreign financial signing Setup outbound"));
        }
        b.check_bounds()?;
        if self.signing_services[i].wire_phase != G_SETUP_REVIEW
            || self.core.phase.signing_phase(i) != G_SETUP_ADMITTED
        {
            return Err(rejected("financial signing Setup send phase"));
        }
        if self.core.phase.signing_send_restricted(i,G_SETUP_ADMITTED)?{outbound.consumed=true;return Ok(FinancialSendProgressV1::Restricted);}
        outbound.consumed = true;
        let progress=self.send_signing_positive(
            b.wire.original.actor.signer_role,
            &GP::PrepareOnce {
                setup: b.wire.clone(),
            },b.ceiling)?;
        if progress==FinancialSendProgressV1::Sent{self.signing_services[i].wire_phase = G_SETUP_ADMITTED;}Ok(progress)
    }
    pub fn send_signing_serve(&mut self,outbound:FinancialSigningServeOutboundV1)->Result<()>{self.try_send_signing_serve(outbound)?.require_sent()}
    pub fn try_send_signing_serve(
        &mut self,
        mut outbound: FinancialSigningServeOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = &outbound.binding;
        let i = b.slot();
        if !Arc::ptr_eq(&self.core, b.core()) {
            return Err(rejected("foreign financial signing Serve outbound"));
        }
        b.check_bounds()?;
        if self.signing_services[i].wire_phase != G_REVIEW || self.core.phase.signing_phase(i) != G_SERVING
        {
            return Err(rejected("financial signing Serve send phase"));
        }
        if self.core.phase.signing_send_restricted(i,G_SERVING)?{outbound.consumed=true;return Ok(FinancialSendProgressV1::Restricted);}
        outbound.consumed = true;
        let progress=self.send_signing_positive(
            b.data.original.actor.signer_role,
            &GP::Serve {
                setup_challenge: b.setup.wire.setup_challenge.clone(),
                witness_instance: b.instance.clone(),
                serve_challenge: b.challenge.clone(),
                presentation_digest: b.data.presentation_digest.clone(),
            },b.review_ceiling)?;
        if progress==FinancialSendProgressV1::Sent{self.signing_services[i].wire_phase = G_SERVING;}Ok(progress)
    }
    /// Restriction only: stops an existing actual service. It cannot stand in
    /// for a successful S effect or authorize another source/service purpose.
    pub fn finish_signing_service(&mut self,role:Target)->Result<()>{
        self.core.check_action_restrictions()?;let i=role.index();let slot=&mut self.signing_services[i];
        if !slot.serving_ack||slot.finish_sent||slot.failed||slot.cancel_sent||slot.disposed{return Err(rejected("Signing Finish without current service"));}
        let b=slot.review.as_ref().ok_or_else(||rejected("Signing Finish review missing"))?;b.setup.entry.check_custody()?;
        self.core.phase.signing_step(i,G_SERVING,G_DONE)?;slot.finish_sent=true;slot.wire_phase=G_DONE;
        let packet=GP::FinishService{setup_challenge:b.setup.wire.setup_challenge.clone(),witness_instance:b.instance.clone(),presentation_digest:b.data.presentation_digest.clone()};
        self.send_signing(role,&packet)
    }
    pub fn try_receive_signing(&mut self) -> Result<Option<CoordinatorFinancialSigningEventV1>> {
        let result = self.receive_signing_inner();
        if result.is_err() {
            self.core.close();
        }
        result
    }
    fn receive_signing_inner(&mut self) -> Result<Option<CoordinatorFinancialSigningEventV1>> {
        self.transport_check()?;
        for role in [Target::Signer1, Target::Signer2] {
            let i = role.index();
            if self.signing_services[i].closed {
                continue;
            }
            let Some(packet) = self
                .tree
                .as_ref()
                .ok_or_else(|| rejected("financial signing tree consumed"))?
                .financial_signing(role)?
                .financial_signing_receive()?
            else {
                continue;
            };
            let slot = &mut self.signing_services[i];
            if let Some(c) = slot.cleanup {
                crate::channel::require_time(c)?;
            }
            let event = match packet {
                GP::Display {
                    setup_challenge,
                    witness_instance,
                    serve_challenge,
                    service_ceiling_ms,
                    data,
                } => {
                    data.validate()?;
                    let setup = slot
                        .setup
                        .as_ref()
                        .ok_or_else(|| rejected("unsolicited financial signing Display"))?;
                    if slot.wire_phase != G_SETUP_ADMITTED
                        || slot.display.is_some()
                        || setup_challenge != setup.wire.setup_challenge
                        || data.original != setup.wire.original
                        || service_ceiling_ms==0 || service_ceiling_ms>setup.wire.original.source_ceiling_ms
                        || data.network_profile_id != setup.wire.inputs.selectors.network_profile_id
                        || data.endpoint!=setup.wire.inputs.selectors.endpoint || data.server_name!=setup.wire.inputs.selectors.server_name
                        || data.witness_id!=setup.wire.inputs.selectors.witness_id || data.pinned_server_certificate_digest!=setup.wire.inputs.selectors.pinned_server_certificate_digest
                        || !state::hash(&witness_instance)
                        || !state::hash(&serve_challenge)
                    {
                        return Err(rejected("financial signing Display binding"));
                    }
                    slot.wire_phase = G_REVIEW;
                    slot.display = Some(data.clone());
                    slot.identity = Some((witness_instance.clone(), serve_challenge.clone()));
                    let now = Instant::now();
                    let wall = state::wall_ms()?;
                    let service_ceiling=self.clocks.restrict_received(PROFILE,service_ceiling_ms,setup.entry.original_source,now)?;
                    let review_ceiling=setup.ceiling.min(service_ceiling).min(wall_ceiling(now,wall,data.prepared_at_ms,data.expires_at_ms)?);
                    let b=Arc::new(GReview{setup:Arc::clone(setup),data,instance:witness_instance,challenge:serve_challenge,
                        service_ceiling_ms,service_ceiling,review_ceiling,last_wall:AtomicU64::new(wall)});
                    slot.review = Some(Arc::clone(&b));
                    // Validate all original clocks/source BEFORE classifying only
                    // the exact expected-phase R race as a restricted receive.
                    b.check_bounds()?;
                    if !received_signing_progress(&self.core.phase, i, G_SETUP_ADMITTED, G_REVIEW)?
                    {
                        CoordinatorFinancialSigningEventV1::Restricted(role)
                    } else {
                        CoordinatorFinancialSigningEventV1::Display(
                            FinancialSigningReviewTicketV1 {
                                binding: b,
                                consumed: false,
                            },
                        )
                    }
                }
                GP::Serving {
                    setup_challenge,
                    witness_instance,
                    serve_challenge,
                    presentation_digest,
                } => {
                    let b = slot
                        .review
                        .as_ref()
                        .ok_or_else(|| rejected("financial signing Serving before review"))?;
                    if slot.wire_phase != G_SERVING
                        || slot.serving_ack
                        || setup_challenge != b.setup.wire.setup_challenge
                        || witness_instance != b.instance
                        || serve_challenge != b.challenge
                        || presentation_digest != b.data.presentation_digest
                    {
                        return Err(rejected("financial signing Serving binding"));
                    }
                    slot.serving_ack = true;
                    b.service_bounds()?;
                    if self.core.phase.signing_send_restricted(i,G_SERVING)? {
                        CoordinatorFinancialSigningEventV1::Restricted(role)
                    } else {
                        CoordinatorFinancialSigningEventV1::Serving(FinancialSigningServingV1 {
                            binding: Arc::clone(b),
                        })
                    }
                }
                GP::PreparationFailed { setup_challenge } => {
                    if slot.failed
                        || slot.display.is_some()
                        || slot
                            .setup
                            .as_ref()
                            .is_none_or(|b| b.wire.setup_challenge != setup_challenge)
                    {
                        return Err(rejected("financial signing preparation failure binding"));
                    }
                    slot.failed = true;
                    self.core.phase.revoke();
                    CoordinatorFinancialSigningEventV1::PreparationFailed(role)
                }
                GP::ServiceFailed {
                    setup_challenge,
                    witness_instance,
                    presentation_digest,
                } => {
                    let setup = slot
                        .setup
                        .as_ref()
                        .ok_or_else(|| rejected("financial signing failure before Setup"))?;
                    let data = slot
                        .display
                        .as_ref()
                        .ok_or_else(|| rejected("financial signing failure before Display"))?;
                    if slot.failed
                        || slot.disposed
                        || setup_challenge != setup.wire.setup_challenge
                        || slot
                            .identity
                            .as_ref()
                            .is_none_or(|(w, _)| w != &witness_instance)
                        || presentation_digest != data.presentation_digest
                    {
                        return Err(rejected("financial signing service failure binding"));
                    }
                    slot.failed = true;
                    self.core.phase.revoke();
                    CoordinatorFinancialSigningEventV1::ServiceFailed(role)
                }
                GP::Disposed {
                    coordinator,
                    session,
                    cleanup_ceiling_ms,
                } => {
                    if coordinator != self.coordinator
                        || session != self.session
                        || slot.disposed
                        || (!slot.finish_sent && !slot.cancel_sent && !slot.failed)
                    {
                        return Err(rejected("financial signing disposal binding"));
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
                    CoordinatorFinancialSigningEventV1::Disposed(role)
                }
                GP::PurposeClosed {
                    coordinator,
                    session,
                } => {
                    if coordinator != self.coordinator
                        || session != self.session
                        || !slot.disposed
                        || !slot.close_sent
                        || slot.closed
                    {
                        return Err(rejected("financial signing close binding"));
                    }
                    slot.closed = true;
                    CoordinatorFinancialSigningEventV1::PurposeClosed(role)
                }
                _ => return Err(rejected("unexpected financial signing observation")),
            };
            return Ok(Some(event));
        }
        Ok(None)
    }
    pub fn close_signing_purpose(&mut self, role: Target) -> Result<()> {
        let slot = &mut self.signing_services[role.index()];
        if !slot.disposed || slot.close_sent {
            return Err(rejected("financial signing close before disposal"));
        }
        let original = slot
            .cleanup
            .ok_or_else(|| rejected("financial signing disposal cutoff missing"))?;
        slot.cleanup = Some(
            self.clocks
                .retain_cleanup(slot.cleanup, original, Instant::now())?,
        );
        slot.close_sent = true;
        self.send_signing(
            role,
            &GP::ClosePurpose {
                coordinator: self.coordinator.clone(),
                session: self.session.clone(),
            },
        )
    }
    pub(super) fn cancel_signing_services(&mut self) -> Result<()> {
        for role in [Target::Signer1, Target::Signer2] {
            let slot = &mut self.signing_services[role.index()];
            if slot.closed || slot.cancel_sent {
                continue;
            }
            slot.cancel_sent = true;
            self.send_signing(
                role,
                &GP::Cancel {
                    coordinator: self.coordinator.clone(),
                    session: self.session.clone(),
                },
            )?;
        }
        Ok(())
    }
}
fn received_signing_progress(phase:&Phases,slot:usize,from:u8,to:u8)->Result<bool>{
    if phase.signing_send_restricted(slot,from)?{return Ok(false);}
    match phase.signing_step(slot,from,to){
        Ok(())=>Ok(!phase.signing_send_restricted(slot,to)?),
        Err(error)=>{if phase.signing_send_restricted(slot,from)?{Ok(false)}else{Err(error)}}
    }
}
impl CGSlot {
    pub(super) fn retirement_idle(&self)->bool{self.setup.is_none()}

    pub(super) fn closed(&self) -> bool {
        self.closed
    }
    pub(super) fn observe_active(&self, core: &Core, i: usize) -> Result<()> {
        match core.phase.signing_phase(i) {
            G_SETUP_REVIEW | G_SETUP_ADMITTED => self
                .setup
                .as_ref()
                .ok_or_else(|| rejected("active financial signing Setup missing"))?
                .check(),
            G_REVIEW => self
                .review
                .as_ref()
                .ok_or_else(|| rejected("active financial signing review missing"))?
                .check(),
            G_SERVING => self.review.as_ref().ok_or_else(||rejected("active Signing service missing"))?.service_check(),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signing_receive_race_does_not_mask_wrong_phase_or_issue_progress() {
        let p = Phases::new();
        p.signing_step(0, 0, G_SETUP_ADMITTED).unwrap();
        p.revoke();
        assert!(!received_signing_progress(&p, 0, G_SETUP_ADMITTED, G_REVIEW).unwrap());
        assert_eq!(p.signing_phase(0), G_SETUP_ADMITTED);
        assert!(received_signing_progress(&p, 0, G_REVIEW, G_SERVING).is_err());
    }
    #[test]
    fn signing_slots_share_restriction_without_aliasing_append_or_signer() {
        let p = Phases::new();
        p.signing_step(0, 0, G_REVIEW).unwrap();
        p.signing_step(1, 0, G_REVIEW).unwrap();
        assert_eq!(p.witness_phase(0), 0);
        assert_eq!(p.phase(0), 0);
        p.signing_step(0, G_REVIEW, G_SERVING).unwrap();
        p.revoke();
        assert!(p.signing_step(1, G_REVIEW, G_SERVING).is_err());
        assert_eq!(p.signing_phase(0), G_SERVING);
        assert_eq!(p.signing_phase(1), G_REVIEW);
    }
}

#[cfg(test)]mod positive_receive_snapshot_tests{
    use super::*;
    #[test]fn signing_receive_q_and_wrong_phase_are_fatal_even_after_r(){
        let p=Phases::new();p.signing_step(0,0,G_SETUP_ADMITTED).unwrap();p.begin_quiescence(p.snapshot()).unwrap();p.revoke();
        assert!(received_signing_progress(&p,0,G_SETUP_ADMITTED,G_REVIEW).is_err());
        let p=Phases::new();p.signing_step(0,0,G_SETUP_ADMITTED).unwrap();p.revoke();
        assert!(!received_signing_progress(&p,0,G_SETUP_ADMITTED,G_REVIEW).unwrap());
        assert!(received_signing_progress(&p,0,G_REVIEW,G_REVIEW).is_err());
    }
}
