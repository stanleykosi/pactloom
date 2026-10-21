//! Distinct original-result Read and exact same-original-Host Return.
use super::activate::ActivateReview;
use super::signing::{FinancialSigningServingV1, SigningServiceLease};
use super::v3_entry::ReturnTransportBounds;
use super::*;
use crate::signer_return_data::*;
use crate::{
    SignerSignCommittedV1, SignerSignExactPresentationV1, SignerWalletObservedV1,
    SignerWalletOriginalV1,
};
use std::sync::atomic::AtomicU64;
use std::time::Duration;
trait Presentation: Clone {
    fn validate(&self) -> Result<()>;
    fn original(&self) -> &SignerWalletOriginalV1;
    fn observed(&self) -> &SignerWalletObservedV1;
    fn actor(&self) -> &FinancialActorContextV1;
    fn digest(&self) -> &str;
    fn ceiling(&self) -> u64;
    fn times(&self) -> (u64, u64);
    fn service(&self) -> u64;
    fn writer(&self) -> u64;
    fn transport(&self) -> (u64, u64, u64, u64);
}
impl Presentation for SignerReturnReadPresentationV1 {
    fn validate(&self) -> Result<()> {
        self.validate()
    }
    fn original(&self) -> &SignerWalletOriginalV1 {
        &self.facts.original
    }
    fn observed(&self) -> &SignerWalletObservedV1 {
        &self.facts.observed
    }
    fn actor(&self) -> &FinancialActorContextV1 {
        &self.actor
    }
    fn digest(&self) -> &str {
        &self.presentation_digest
    }
    fn ceiling(&self) -> u64 {
        self.read_ceiling_ms
    }
    fn times(&self) -> (u64, u64) {
        (self.facts.reviewed_at_ms, self.facts.expires_at_ms)
    }
    fn service(&self) -> u64 {
        self.service_ceiling_ms
    }
    fn transport(&self) -> (u64, u64, u64, u64) {
        (
            self.channel_ceiling_ms,
            self.material_ceiling_ms,
            self.channel_expires_at_ms,
            self.material_expires_at_ms,
        )
    }
    fn writer(&self) -> u64 {
        self.writer_session_ceiling_ms
    }
}
impl Presentation for SignerReturnExactPresentationV1 {
    fn validate(&self) -> Result<()> {
        self.validate()
    }
    fn original(&self) -> &SignerWalletOriginalV1 {
        &self.facts.read.facts.original
    }
    fn observed(&self) -> &SignerWalletObservedV1 {
        &self.facts.read.facts.observed
    }
    fn actor(&self) -> &FinancialActorContextV1 {
        &self.actor
    }
    fn digest(&self) -> &str {
        &self.presentation_digest
    }
    fn ceiling(&self) -> u64 {
        self.return_ceiling_ms
    }
    fn times(&self) -> (u64, u64) {
        (self.facts.reviewed_at_ms, self.facts.expires_at_ms)
    }
    fn service(&self) -> u64 {
        self.service_ceiling_ms
    }
    fn transport(&self) -> (u64, u64, u64, u64) {
        (
            self.channel_ceiling_ms,
            self.material_ceiling_ms,
            self.channel_expires_at_ms,
            self.material_expires_at_ms,
        )
    }
    fn writer(&self) -> u64 {
        self.writer_session_ceiling_ms
    }
}
struct Binding<P: Presentation> {
    activation: Arc<ActivateReview>,
    p: P,
    deadline: Instant,
    read_deadline: Instant,
    last_wall: AtomicU64,
    transport: ReturnTransportBounds,
}
impl<P: Presentation> Binding<P> {
    fn new(a: Arc<ActivateReview>, p: P, transport: ReturnTransportBounds) -> Result<Arc<Self>> {
        p.validate()?;
        if p.transport()
            != (
                transport.channel_ceiling,
                transport.material_ceiling,
                transport.channel_wall,
                transport.material_wall,
            )
        {
            return Err(rejected("Return replaced original transport/material"));
        }
        a.wallet_bounds()?;
        let now = Instant::now();
        let (t, e) = p.times();
        let deadline = a
            .read
            .entry
            .clocks
            .restrict_received(
                PROFILE,
                p.ceiling(),
                a.read.service.deadline.min(a.read.writer_deadline),
                now,
            )?
            .min(wall_ceiling(now, state::wall_ms()?, t, e)?);
        let b = Arc::new(Self {
            activation: a,
            p,
            deadline,
            read_deadline: deadline,
            last_wall: AtomicU64::new(state::wall_ms()?),
            transport,
        });
        b.bounds()?;
        Ok(b)
    }
    fn core(&self) -> &Arc<Core> {
        self.activation.wallet_core()
    }
    fn slot(&self) -> usize {
        self.activation.wallet_slot()
    }
    fn bounds(&self) -> Result<()> {
        self.activation.wallet_bounds()?;
        let w = state::wall_ms()?;
        let old = self.last_wall.fetch_max(w, Ordering::AcqRel);
        let (a, b) = self.p.times();
        if w < old
            || w < a
            || w >= b
            || w >= self.transport.channel_wall
            || w >= self.transport.material_wall
            || Instant::now() >= self.transport.channel
            || Instant::now() >= self.transport.material
            || Instant::now() >= self.deadline
        {
            return Err(rejected("sign original action expired"));
        }
        Ok(())
    }
    fn current(&self, phase: u8) -> Result<()> {
        self.bounds()?;
        self.core().check_action_restrictions()?;
        if self.core().phase.phase(self.slot()) != phase {
            return Err(rejected("sign consumed/reordered"));
        }
        Ok(())
    }
}
struct Slot<P: Presentation, R> {
    binding: Option<Arc<Binding<P>>>,
    wire: Option<P>,
    result: Option<R>,
    phase: u8,
    reported: bool,
}
impl<P: Presentation, R> Default for Slot<P, R> {
    fn default() -> Self {
        Self {
            binding: None,
            wire: None,
            result: None,
            phase: 0,
            reported: false,
        }
    }
}
#[derive(Default)]
pub(super) struct ReturnSlots {
    read: Slot<SignerReturnReadPresentationV1, SignerReturnPreparedV1>,
    exact: Slot<SignerReturnExactPresentationV1, SignerReturnCompletedV1>,
    terminal: bool,
}
fn same_original<P: Presentation>(
    p: &P,
    w: &SignerSignExactPresentationV1,
    r: &SignerSignCommittedV1,
    service: u64,
    writer: u64,
) -> bool {
    p.original() == &w.facts.original
        && p.observed() == &w.facts.observed
        && p.actor() == &w.actor
        && p.service() == service
        && p.writer() == writer
        && r.sign_presentation_digest == w.presentation_digest
}
fn exact_matches(
    p: &SignerReturnExactPresentationV1,
    r: &SignerReturnReadPresentationV1,
    d: &SignerReturnPreparedV1,
) -> bool {
    p.actor == r.actor
        && p.facts.read == *r
        && d.read_presentation_digest == r.presentation_digest
        && p.facts.preview_digest == d.preview_digest
        && p.facts.reviewed_digest == d.reviewed_digest
        && p.facts.signature_set_digest == d.signature_set_digest
        && p.transport() == r.transport()
}
fn completed_matches(d: &SignerReturnCompletedV1, p: &SignerReturnExactPresentationV1) -> bool {
    d.return_presentation_digest == p.presentation_digest
        && d.preview_digest == p.facts.preview_digest
        && d.result_digest == p.facts.read.facts.signed.result_digest
        && d.outbox_digest == p.facts.read.facts.signed.outbox_digest
}
pub struct SignerReturnReadTicketV1 {
    binding: Arc<Binding<SignerReturnReadPresentationV1>>,
    consumed: bool,
}
impl SignerReturnReadTicketV1 {
    pub fn presentation(&self) -> &SignerReturnReadPresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(68)
    }
}
impl Drop for SignerReturnReadTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerReturnReadOutboundV1 {
    binding: Arc<Binding<SignerReturnReadPresentationV1>>,
    service: SigningServiceLease,
    consumed: bool,
}
impl Drop for SignerReturnReadOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerReturnReadFinalV1 {
    binding: Arc<Binding<SignerReturnReadPresentationV1>>,
    consumed: bool,
}
impl SignerReturnReadFinalV1 {
    pub fn original_channel_deadline(&self) -> Instant {
        self.binding.transport.channel
    }
    pub fn original_material_deadline(&self) -> Instant {
        self.binding.transport.material
    }

    pub fn presentation(&self) -> &SignerReturnReadPresentationV1 {
        &self.binding.p
    }
    pub fn facts(&self) -> &SignerReturnReadFactsV1 {
        &self.binding.p.facts
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(69)
    }
    pub fn original_read_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.activation.read.entry.original_source
    }
    pub fn original_service_deadline(&self) -> Instant {
        self.binding.activation.read.service.deadline
    }
    pub fn original_writer_session_deadline(&self) -> Instant {
        self.binding.activation.read.writer_deadline
    }
}
impl Drop for SignerReturnReadFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_return_read(
        &self,
        mut ticket: SignerReturnReadTicketV1,
        serving: &FinancialSigningServingV1,
    ) -> Result<SignerReturnReadOutboundV1> {
        let b = &ticket.binding;
        if !Arc::ptr_eq(&self.core, b.core()) {
            self.revoke();
            return Err(rejected("sign foreign native Core"));
        }
        serving.matches_acquire(&self.core, &b.activation.read.acquired_presentation)?;
        let service = serving.retain()?;
        b.activation
            .read
            .service
            .require_same(&service.correlation())?;
        ticket.check_current()?;
        service.check()?;
        self.core.phase.step(b.slot(), 68, 69)?;
        ticket.consumed = true;
        Ok(SignerReturnReadOutboundV1 {
            binding: Arc::clone(b),
            service,
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn try_send_return_read(
        &mut self,
        mut out: SignerReturnReadOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = Arc::clone(&out.binding);
        let i = b.slot();
        let result = (|| {
            let s = &self.slots[i]
                .as_ref()
                .ok_or_else(|| rejected("sign missing source"))?
                .activate
                .wallet
                .sign
                .returning
                .read;
            if !Arc::ptr_eq(&self.core, b.core())
                || s.phase != 68
                || s.binding.as_ref().is_none_or(|v| !Arc::ptr_eq(v, &b))
            {
                return Err(rejected("sign outbound mismatch/replay"));
            }
            b.bounds()?;
            out.service.check()?;
            b.activation
                .read
                .service
                .require_same(&out.service.correlation())?;
            if self.core.phase.source_send_restricted(i, 69)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::ReturnReadFinal {
                    role: b.p.actor.signer_role,
                    presentation_digest: b.p.presentation_digest.clone(),
                },
                b.deadline,
            )?;
            if r == FinancialSendProgressV1::Sent {
                self.slots[i]
                    .as_mut()
                    .unwrap()
                    .activate
                    .wallet
                    .sign
                    .returning
                    .read
                    .phase = 69;
            }
            Ok(r)
        })();
        out.consumed = true;
        if result.is_err() {
            self.core.phase.revoke();
        }
        result
    }
}
pub struct SignerReturnExactTicketV1 {
    binding: Arc<Binding<SignerReturnExactPresentationV1>>,
    consumed: bool,
}
impl SignerReturnExactTicketV1 {
    pub fn presentation(&self) -> &SignerReturnExactPresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(71)
    }
}
impl Drop for SignerReturnExactTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerReturnExactOutboundV1 {
    binding: Arc<Binding<SignerReturnExactPresentationV1>>,
    service: SigningServiceLease,
    consumed: bool,
}
impl Drop for SignerReturnExactOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerReturnExactFinalV1 {
    binding: Arc<Binding<SignerReturnExactPresentationV1>>,
    consumed: bool,
}
impl SignerReturnExactFinalV1 {
    pub fn original_read_deadline(&self) -> Instant {
        self.binding.read_deadline
    }
    pub fn original_channel_deadline(&self) -> Instant {
        self.binding.transport.channel
    }
    pub fn original_material_deadline(&self) -> Instant {
        self.binding.transport.material
    }

    pub fn presentation(&self) -> &SignerReturnExactPresentationV1 {
        &self.binding.p
    }
    pub fn facts(&self) -> &SignerReturnExactFactsV1 {
        &self.binding.p.facts
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(72)
    }
    pub fn original_return_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.activation.read.entry.original_source
    }
    pub fn original_service_deadline(&self) -> Instant {
        self.binding.activation.read.service.deadline
    }
    pub fn original_writer_session_deadline(&self) -> Instant {
        self.binding.activation.read.writer_deadline
    }
}
impl Drop for SignerReturnExactFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_return_exact(
        &self,
        mut ticket: SignerReturnExactTicketV1,
        serving: &FinancialSigningServingV1,
    ) -> Result<SignerReturnExactOutboundV1> {
        let b = &ticket.binding;
        if !Arc::ptr_eq(&self.core, b.core()) {
            self.revoke();
            return Err(rejected("sign foreign native Core"));
        }
        serving.matches_acquire(&self.core, &b.activation.read.acquired_presentation)?;
        let service = serving.retain()?;
        b.activation
            .read
            .service
            .require_same(&service.correlation())?;
        ticket.check_current()?;
        service.check()?;
        self.core.phase.step(b.slot(), 71, 72)?;
        ticket.consumed = true;
        Ok(SignerReturnExactOutboundV1 {
            binding: Arc::clone(b),
            service,
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn try_send_return_exact(
        &mut self,
        mut out: SignerReturnExactOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = Arc::clone(&out.binding);
        let i = b.slot();
        let result = (|| {
            let s = &self.slots[i]
                .as_ref()
                .ok_or_else(|| rejected("sign missing source"))?
                .activate
                .wallet
                .sign
                .returning
                .exact;
            if !Arc::ptr_eq(&self.core, b.core())
                || s.phase != 71
                || s.binding.as_ref().is_none_or(|v| !Arc::ptr_eq(v, &b))
            {
                return Err(rejected("sign outbound mismatch/replay"));
            }
            b.bounds()?;
            out.service.check()?;
            b.activation
                .read
                .service
                .require_same(&out.service.correlation())?;
            if self.core.phase.source_send_restricted(i, 72)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::ReturnExactFinal {
                    role: b.p.actor.signer_role,
                    presentation_digest: b.p.presentation_digest.clone(),
                },
                b.deadline,
            )?;
            if r == FinancialSendProgressV1::Sent {
                self.slots[i]
                    .as_mut()
                    .unwrap()
                    .activate
                    .wallet
                    .sign
                    .returning
                    .exact
                    .phase = 72;
            }
            Ok(r)
        })();
        out.consumed = true;
        if result.is_err() {
            self.core.phase.revoke();
        }
        result
    }
}
impl SignerFinancialWorkflowOriginV1 {
    pub fn offer_return_read(
        &mut self,
        facts: SignerReturnReadFactsV1,
        original_read: Instant,
    ) -> Result<SignerReturnReadPresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        let transport = self.v3_entry.return_transport_bounds()?;
        let (a, _) = self.activate.wallet_predecessor()?;
        let a = Arc::clone(a);
        let (w, r) = self.activate.wallet.sign.return_predecessor()?;
        let w = w.clone();
        let r = r.clone();
        a.wallet_bounds()?;
        if self.activate.wallet.sign.returning.read.binding.is_some()
            || self.activate.wallet.sign.returning.terminal
            || original_read > a.read.service.deadline
            || original_read > a.read.writer_deadline
            || original_read > transport.channel
            || original_read > transport.material
            || original_read > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected("Return one original Read window"));
        }
        let mut p = SignerReturnReadPresentationV1 {
            actor: a.wire.actor.clone(),
            facts,
            notice: READ_NOTICE.into(),
            challenge: state::nonce()?,
            source_ceiling_ms: a.wire.source_ceiling_ms,
            read_ceiling_ms: self.clocks.restrictive_offset(
                original_read,
                a.read
                    .service
                    .deadline
                    .min(a.read.writer_deadline)
                    .min(transport.channel)
                    .min(transport.material),
            )?,
            service_ceiling_ms: a.read.service.correlation().service_ceiling_ms,
            writer_session_ceiling_ms: self
                .clocks
                .restrictive_offset(a.read.writer_deadline, a.read.entry.original_source)?,
            channel_ceiling_ms: transport.channel_ceiling,
            material_ceiling_ms: transport.material_ceiling,
            channel_expires_at_ms: transport.channel_wall,
            material_expires_at_ms: transport.material_wall,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        if !same_original(
            &p,
            &w,
            &r,
            p.service_ceiling_ms,
            p.writer_session_ceiling_ms,
        ) || p.facts.signed != r
        {
            return Err(rejected("Return actual signed predecessor changed"));
        }
        let mut b = Binding::new(a, p.clone(), transport)?;
        Arc::get_mut(&mut b)
            .ok_or_else(|| rejected("Return binding escaped"))?
            .deadline = original_read;
        Arc::get_mut(&mut b)
            .ok_or_else(|| rejected("Return Read clock binding escaped"))?
            .read_deadline = original_read;
        b.current(67)?;
        self.core.phase.step(self.target.index(), 67, 68)?;
        self.activate.wallet.sign.returning.read = Slot {
            binding: Some(b),
            wire: Some(p.clone()),
            phase: 68,
            ..Default::default()
        };
        self.send_return_observation(
            &Packet::ReturnReadDisplay {
                presentation: p.clone(),
            },
            original_read,
        )?;
        Ok(p)
    }
    pub fn offer_return_exact(
        &mut self,
        mut completed: SignerReturnReadCompletedV1,
        facts: SignerReturnExactFactsV1,
        original_return: Instant,
    ) -> Result<SignerReturnExactPresentationV1> {
        completed.check_current()?;
        facts.validate()?;
        let rb = Arc::clone(&completed.binding);
        let s = &self.activate.wallet.sign.returning;
        if !Arc::ptr_eq(&self.core, rb.core())
            || s.read.binding.as_ref().is_none_or(|b| !Arc::ptr_eq(b, &rb))
            || s.exact.binding.is_some()
            || s.terminal
            || original_return > rb.activation.read.service.deadline
            || original_return > rb.activation.read.writer_deadline
            || original_return > rb.transport.channel
            || original_return > rb.transport.material
            || original_return > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected(
                "Return Exact original completed Read lineage/window",
            ));
        }
        let d = SignerReturnPreparedV1 {
            read_presentation_digest: rb.p.presentation_digest.clone(),
            preview_digest: facts.preview_digest.clone(),
            reviewed_digest: facts.reviewed_digest.clone(),
            signature_set_digest: facts.signature_set_digest.clone(),
        };
        d.validate()?;
        let mut p = SignerReturnExactPresentationV1 {
            actor: rb.p.actor.clone(),
            facts,
            notice: EXACT_NOTICE.into(),
            challenge: state::nonce()?,
            source_ceiling_ms: rb.p.source_ceiling_ms,
            return_ceiling_ms: self.clocks.restrictive_offset(
                original_return,
                rb.activation
                    .read
                    .service
                    .deadline
                    .min(rb.activation.read.writer_deadline)
                    .min(rb.transport.channel)
                    .min(rb.transport.material),
            )?,
            service_ceiling_ms: rb.p.service_ceiling_ms,
            writer_session_ceiling_ms: rb.p.writer_session_ceiling_ms,
            channel_ceiling_ms: rb.p.channel_ceiling_ms,
            material_ceiling_ms: rb.p.material_ceiling_ms,
            channel_expires_at_ms: rb.p.channel_expires_at_ms,
            material_expires_at_ms: rb.p.material_expires_at_ms,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        if !exact_matches(&p, &rb.p, &d) {
            return Err(rejected("Return Exact changed actual prepared Read"));
        }
        let mut b = Binding::new(Arc::clone(&rb.activation), p.clone(), rb.transport)?;
        Arc::get_mut(&mut b)
            .ok_or_else(|| rejected("Return Exact binding escaped"))?
            .deadline = original_return;
        Arc::get_mut(&mut b)
            .ok_or_else(|| rejected("Return Exact clock binding escaped"))?
            .read_deadline = rb.deadline;
        completed.check_current()?;
        completed.consumed = true;
        self.activate.wallet.sign.returning.read.result = Some(d.clone());
        self.activate.wallet.sign.returning.read.reported = true;
        self.activate.wallet.sign.returning.read.phase = 70;
        self.send_return_observation(
            &Packet::ReturnPrepared {
                role: self.target,
                data: d,
            },
            original_return,
        )?;
        self.core.phase.step(self.target.index(), 70, 71)?;
        self.activate.wallet.sign.returning.exact = Slot {
            binding: Some(b),
            wire: Some(p.clone()),
            phase: 71,
            ..Default::default()
        };
        self.send_return_observation(
            &Packet::ReturnExactDisplay {
                presentation: p.clone(),
            },
            original_return,
        )?;
        Ok(p)
    }
    pub fn report_return_completed(&mut self, data: SignerReturnCompletedV1) -> Result<()> {
        data.validate()?;
        let s = &mut self.activate.wallet.sign.returning.exact;
        let b = s
            .binding
            .as_ref()
            .ok_or_else(|| rejected("Return result before Exact"))?;
        if s.reported
            || self.core.phase.phase(self.target.index()) != 73
            || !completed_matches(&data, &b.p)
        {
            return Err(rejected("Return result mismatch/replay"));
        }
        s.result = Some(data.clone());
        s.reported = true;
        s.phase = 73;
        let deadline = b.activation.read.entry.original_source;
        self.send_return_observation(
            &Packet::ReturnCompleted {
                role: self.target,
                data,
            },
            deadline,
        )
    }
}
impl SignerReturnReadFinalV1 {
    pub fn finish_read(mut self) -> Result<SignerReturnReadCompletedV1> {
        self.check_current()?;
        self.binding
            .core()
            .phase
            .step(self.binding.slot(), 69, 70)?;
        self.consumed = true;
        Ok(SignerReturnReadCompletedV1 {
            binding: Arc::clone(&self.binding),
            consumed: false,
        })
    }
}
/// Denial-only custody after the one original Read. No SQL/network methods and
/// no data constructor; awaiting HostPrepared cannot reuse the Read permission.
pub struct SignerReturnReadCompletedV1 {
    binding: Arc<Binding<SignerReturnReadPresentationV1>>,
    consumed: bool,
}
impl SignerReturnReadCompletedV1 {
    pub fn check_current(&self) -> Result<()> {
        let b = &self.binding;
        b.activation.wallet_bounds()?;
        b.core().check_action_restrictions()?;
        crate::channel::require_time(b.transport.channel.min(b.transport.material))?;
        let wall = state::wall_ms()?;
        let old = b.last_wall.fetch_max(wall, Ordering::AcqRel);
        if wall < old
            || wall >= b.transport.channel_wall
            || wall >= b.transport.material_wall
            || b.core().phase.phase(b.slot()) != 70
        {
            return Err(rejected("Return completed Read custody expired/reordered"));
        }
        Ok(())
    }
    pub fn presentation(&self) -> &SignerReturnReadPresentationV1 {
        &self.binding.p
    }
    pub fn original_read_deadline(&self) -> Instant {
        self.binding.deadline
    }
    pub fn original_source_deadline(&self) -> Instant {
        self.binding.activation.read.entry.original_source
    }
    pub fn original_service_deadline(&self) -> Instant {
        self.binding.activation.read.service.deadline
    }
    pub fn original_writer_session_deadline(&self) -> Instant {
        self.binding.activation.read.writer_deadline
    }
    pub fn original_channel_deadline(&self) -> Instant {
        self.binding.transport.channel
    }
    pub fn original_material_deadline(&self) -> Instant {
        self.binding.transport.material
    }
}
impl Drop for SignerReturnReadCompletedV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
impl SignerReturnExactFinalV1 {
    pub fn finish_return(mut self) -> Result<()> {
        // Actual pinned sender calls only after same-stream Finished write succeeded.
        if unsafe { libc::getpid() } != self.binding.core().owner_pid
            || unsafe { libc::geteuid() } != self.binding.core().owner_uid
        {
            return Err(rejected("Return original actor changed"));
        }
        self.binding
            .core()
            .phase
            .observe_return_completed(self.binding.slot())?;
        self.consumed = true;
        Ok(())
    }
}
impl SignerFinancialWorkflowOriginV1 {
    pub(in crate::financial_workflow_origin) fn receive_return(
        &mut self,
        p: Packet,
    ) -> Result<SignerFinancialWorkflowRequestV1> {
        let role = p.target()?.ok_or_else(|| rejected("sign role"))?;
        if role != self.target || self.activate.wallet.sign.returning.terminal {
            return Err(rejected("sign role/terminal"));
        }
        match p {
            Packet::ReturnReadFinal {
                presentation_digest,
                ..
            } => {
                let s = &mut self.activate.wallet.sign.returning.read;
                let b = s
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("sign unsolicited Final"))?;
                if s.phase != 68 || presentation_digest != b.p.presentation_digest {
                    return Err(rejected("sign Final mismatch/replay"));
                }
                b.current(68)?;
                self.core.phase.step(role.index(), 68, 69)?;
                s.phase = 69;
                Ok(SignerFinancialWorkflowRequestV1::ReturnRead {
                    final_action: SignerReturnReadFinalV1 {
                        binding: Arc::clone(b),
                        consumed: false,
                    },
                })
            }
            Packet::ReturnExactFinal {
                presentation_digest,
                ..
            } => {
                let s = &mut self.activate.wallet.sign.returning.exact;
                let b = s
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("sign unsolicited Final"))?;
                if s.phase != 71 || presentation_digest != b.p.presentation_digest {
                    return Err(rejected("sign Final mismatch/replay"));
                }
                b.current(71)?;
                self.core.phase.step(role.index(), 71, 72)?;
                s.phase = 72;
                Ok(SignerFinancialWorkflowRequestV1::ReturnExact {
                    final_action: SignerReturnExactFinalV1 {
                        binding: Arc::clone(b),
                        consumed: false,
                    },
                })
            }
            _ => Err(rejected("wrong sign request")),
        }
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub(in crate::financial_workflow_origin) fn receive_return_event(
        &mut self,
        p: Packet,
    ) -> Result<CoordinatorFinancialEventV1> {
        let role = p.target()?.ok_or_else(|| rejected("sign event role"))?;
        let i = role.index();
        let transport = if matches!(
            p,
            Packet::ReturnReadDisplay { .. } | Packet::ReturnExactDisplay { .. }
        ) {
            Some(self.v3_entries[i].return_transport_bounds()?)
        } else {
            None
        };
        let slot = self.slots[i]
            .as_mut()
            .ok_or_else(|| rejected("sign missing financial source"))?;
        let (a, _) = slot.activate.wallet_predecessor()?;
        let a = Arc::clone(a);
        let (w, r) = slot.activate.wallet.sign.return_predecessor()?;
        let w = w.clone();
        let r = r.clone();
        let s = &mut slot.activate.wallet.sign.returning;
        if s.terminal {
            return Err(rejected("sign terminal"));
        }
        let service = a.read.service.correlation().service_ceiling_ms;
        let writer = self
            .clocks
            .restrictive_offset(a.read.writer_deadline, a.read.entry.original_source)?;
        match p {
            Packet::ReturnReadDisplay { presentation } => {
                if presentation.facts.signed != r {
                    return Err(rejected("Return changed actual signed report"));
                }
                if s.read.binding.is_some()
                    || !same_original(&presentation, &w, &r, service, writer)
                {
                    return Err(rejected("sign display predecessor mismatch"));
                }
                let b = Binding::new(
                    a,
                    presentation.clone(),
                    transport
                        .ok_or_else(|| rejected("Return display missing original transport"))?,
                )?;
                s.read.wire = Some(presentation);
                s.read.binding = Some(Arc::clone(&b));
                s.read.phase = 68;
                if !received_workflow_progress(&self.core.phase, i, 67, 68)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::ReturnReadDisplay(
                    SignerReturnReadTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::ReturnExactDisplay { presentation } => {
                if s.exact.binding.is_some()
                    || !same_original(&presentation, &w, &r, service, writer)
                {
                    return Err(rejected("sign display predecessor mismatch"));
                }
                let rp = s
                    .read
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("Exact missing original Read"))?;
                let d = s
                    .read
                    .result
                    .as_ref()
                    .ok_or_else(|| rejected("Exact missing actual prepared"))?;
                if !s.read.reported || s.read.phase != 70 || !exact_matches(&presentation, rp, d) {
                    return Err(rejected("Exact changed prepared source"));
                }
                let mut b = Binding::new(
                    a,
                    presentation.clone(),
                    transport
                        .ok_or_else(|| rejected("Return display missing original transport"))?,
                )?;
                Arc::get_mut(&mut b)
                    .ok_or_else(|| rejected("Return exact binding escaped"))?
                    .read_deadline = s
                    .read
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("Return exact missing original Read clock"))?
                    .deadline;
                s.exact.wire = Some(presentation);
                s.exact.binding = Some(Arc::clone(&b));
                s.exact.phase = 71;
                if !received_workflow_progress(&self.core.phase, i, 70, 71)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::ReturnExactDisplay(
                    SignerReturnExactTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::ReturnPrepared { data, .. } => {
                data.validate()?;
                let t = &mut s.read;
                let p = t
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("sign prepared before Read"))?;
                if t.reported
                    || t.phase != 69
                    || data.read_presentation_digest != p.presentation_digest
                {
                    return Err(rejected("sign prepared mismatch/replay"));
                }
                t.result = Some(data.clone());
                t.reported = true;
                t.phase = 70;
                received_workflow_progress(&self.core.phase, i, 69, 70)?;
                Ok(CoordinatorFinancialEventV1::ReturnPrepared { role, data })
            }
            Packet::ReturnCompleted { data, .. } => {
                data.validate()?;
                let t = &mut s.exact;
                let p = t
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("sign committed before Exact"))?;
                if t.reported || t.phase != 72 || !completed_matches(&data, p) {
                    return Err(rejected("sign committed mismatch/replay"));
                }
                t.result = Some(data.clone());
                t.reported = true;
                t.phase = 73;
                received_workflow_progress(&self.core.phase, i, 72, 73)?;
                Ok(CoordinatorFinancialEventV1::ReturnCompleted { role, data })
            }
            Packet::ReturnFailed { data, .. } => {
                failure_matches(s, &data)?;
                s.terminal = true;
                self.core.phase.revoke();
                Ok(CoordinatorFinancialEventV1::ReturnFailed { role, data })
            }
            _ => Err(rejected("wrong sign event")),
        }
    }
}
fn relay_clock<P: Presentation>(
    p: &P,
    service: Instant,
    writer: Instant,
    clocks: FullWorkflowClocksV1,
    last: &mut u64,
) -> Result<()> {
    p.validate()?;
    let now = Instant::now();
    clocks.restrict_received(PROFILE, p.ceiling(), service.min(writer), now)?;
    let wall = state::wall_ms()?;
    let (a, b) = p.times();
    if wall < *last || wall < a || wall >= b || wall >= p.transport().2 || wall >= p.transport().3 {
        return Err(rejected("sign relay action expired"));
    }
    *last = wall;
    Ok(())
}
impl HostFinancialWorkflowRelayV1 {
    pub(in crate::financial_workflow_origin) fn down_return(&mut self, p: &Packet) -> Result<()> {
        if self.restricted {
            return Err(rejected("sign relay after R"));
        }
        let role = p.target()?.ok_or_else(|| rejected("sign relay role"))?;
        let slot = self.slots[role.index()]
            .as_mut()
            .ok_or_else(|| rejected("sign relay missing source"))?;
        let (_, _, service, writer) = slot.activate.wallet_predecessor()?;
        let deadline = service.deadline;
        let s = &mut slot.activate.wallet.sign.returning;
        if s.terminal {
            return Err(rejected("sign relay terminal"));
        }
        match p {
            Packet::ReturnReadFinal {
                presentation_digest,
                ..
            } => {
                let t = &mut s.read;
                let p = t
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("sign relay before display"))?;
                if t.phase != 68 || presentation_digest != &p.presentation_digest {
                    return Err(rejected("sign relay Final mismatch/replay"));
                }
                relay_clock(p, deadline, writer, self.clocks, &mut slot.last_wall)?;
                t.phase = 69;
                Ok(())
            }
            Packet::ReturnExactFinal {
                presentation_digest,
                ..
            } => {
                let t = &mut s.exact;
                let p = t
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("sign relay before display"))?;
                if t.phase != 71 || presentation_digest != &p.presentation_digest {
                    return Err(rejected("sign relay Final mismatch/replay"));
                }
                relay_clock(p, deadline, writer, self.clocks, &mut slot.last_wall)?;
                t.phase = 72;
                Ok(())
            }
            _ => Err(rejected("wrong sign relay command")),
        }
    }
    pub(in crate::financial_workflow_origin) fn up_return(
        &mut self,
        role: Target,
        p: &Packet,
    ) -> Result<bool> {
        let transport = if matches!(
            p,
            Packet::ReturnReadDisplay { .. } | Packet::ReturnExactDisplay { .. }
        ) && !self.restricted
        {
            Some(self.v3_entries[role.index()].return_transport_bounds(self.clocks)?)
        } else {
            None
        };
        let slot = self.slots[role.index()]
            .as_mut()
            .ok_or_else(|| rejected("sign relay missing source"))?;
        let (a, _, service, writer) = slot.activate.wallet_predecessor()?;
        let service_ceiling = service.correlation().service_ceiling_ms;
        let deadline = service.deadline;
        let writer_ceiling = self
            .clocks
            .restrictive_offset(writer, self.clocks.supervision())?;
        let (w, r) = slot.activate.wallet.sign.return_predecessor()?;
        let w = w.clone();
        let r = r.clone();
        let a = a.clone();
        let s = &mut slot.activate.wallet.sign.returning;
        if s.terminal {
            return Err(rejected("sign relay terminal"));
        }
        match p {
            Packet::ReturnReadDisplay { presentation } => {
                if presentation.facts.signed != r {
                    return Err(rejected("Return relay changed signed report"));
                }
                if self.restricted {
                    return Ok(false);
                }
                let t = transport.ok_or_else(|| rejected("Return missing transport"))?;
                if presentation.transport()
                    != (
                        t.channel_ceiling,
                        t.material_ceiling,
                        t.channel_wall,
                        t.material_wall,
                    )
                {
                    return Err(rejected("Return relay changed transport"));
                }
                if s.read.wire.is_some()
                    || presentation.actor != a.actor
                    || !same_original(presentation, &w, &r, service_ceiling, writer_ceiling)
                {
                    return Err(rejected("sign relay display predecessor"));
                }
                relay_clock(
                    presentation,
                    deadline,
                    writer,
                    self.clocks,
                    &mut slot.last_wall,
                )?;
                s.read.wire = Some(presentation.clone());
                s.read.phase = 68;
                Ok(true)
            }
            Packet::ReturnExactDisplay { presentation } => {
                if self.restricted {
                    return Ok(false);
                }
                let t = transport.ok_or_else(|| rejected("Return missing transport"))?;
                if presentation.transport()
                    != (
                        t.channel_ceiling,
                        t.material_ceiling,
                        t.channel_wall,
                        t.material_wall,
                    )
                {
                    return Err(rejected("Return relay changed transport"));
                }
                if s.exact.wire.is_some()
                    || presentation.actor != a.actor
                    || !same_original(presentation, &w, &r, service_ceiling, writer_ceiling)
                {
                    return Err(rejected("sign relay display predecessor"));
                }
                let rp = s
                    .read
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("relay Exact before Read"))?;
                let d = s
                    .read
                    .result
                    .as_ref()
                    .ok_or_else(|| rejected("relay Exact before actual prepared"))?;
                if s.read.phase != 70 || !s.read.reported || !exact_matches(presentation, rp, d) {
                    return Err(rejected("relay Exact changed prepared source"));
                }
                relay_clock(
                    presentation,
                    deadline,
                    writer,
                    self.clocks,
                    &mut slot.last_wall,
                )?;
                s.exact.wire = Some(presentation.clone());
                s.exact.phase = 71;
                Ok(true)
            }
            Packet::ReturnPrepared { data, .. } => {
                data.validate()?;
                let t = &mut s.read;
                let p = t
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("sign relay prepared before Read"))?;
                if t.reported
                    || t.phase != 69
                    || data.read_presentation_digest != p.presentation_digest
                {
                    return Err(rejected("sign relay prepared mismatch"));
                }
                t.result = Some(data.clone());
                t.reported = true;
                t.phase = 70;
                Ok(true)
            }
            Packet::ReturnCompleted { data, .. } => {
                data.validate()?;
                let t = &mut s.exact;
                let p = t
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("sign relay result before Exact"))?;
                if t.reported || t.phase != 72 || !completed_matches(data, p) {
                    return Err(rejected("sign relay result mismatch"));
                }
                t.result = Some(data.clone());
                t.reported = true;
                t.phase = 73;
                Ok(true)
            }
            Packet::ReturnFailed { data, .. } => {
                failure_matches(s, data)?;
                s.terminal = true;
                Ok(true)
            }
            _ => Err(rejected("wrong sign relay event")),
        }
    }
}
fn failure_matches(s: &ReturnSlots, d: &SignerReturnFailureV1) -> Result<()> {
    d.validate()?;
    let ok = match d.stage {
        SignerReturnFailureStageV1::ReadFailed => {
            s.read
                .wire
                .as_ref()
                .is_some_and(|p| p.presentation_digest == d.presentation_digest)
                && matches!(s.read.phase, 69 | 70)
                && s.exact.phase < 72
        }
        SignerReturnFailureStageV1::ReturnUncertain => {
            s.exact
                .wire
                .as_ref()
                .is_some_and(|p| p.presentation_digest == d.presentation_digest)
                && s.exact.phase == 72
                && !s.exact.reported
        }
    };
    if s.terminal || !ok {
        return Err(rejected("sign failure mismatch/replay"));
    }
    Ok(())
}
impl SignerFinancialWorkflowOriginV1 {
    pub fn report_return_failure(&mut self, data: SignerReturnFailureV1) -> Result<()> {
        failure_matches(&self.activate.wallet.sign.returning, &data)?;
        self.activate.wallet.sign.returning.terminal = true;
        self.core.phase.revoke();
        self.send_return_observation(
            &Packet::ReturnFailed {
                role: self.target,
                data,
            },
            self.clocks.supervision(),
        )
    }
}
impl ReturnSlots {
    pub(super) fn observe_active(&self, phase: u8) -> Result<()> {
        if self.terminal {
            return Err(rejected("sign terminal"));
        }
        match phase {
            68 | 69 => self
                .read
                .binding
                .as_ref()
                .ok_or_else(|| rejected("sign missing Read"))?
                .bounds(),
            71 | 72 => self
                .exact
                .binding
                .as_ref()
                .ok_or_else(|| rejected("sign missing Exact"))?
                .bounds(),
            _ => Ok(()),
        }
    }
}

impl SignerFinancialWorkflowOriginV1 {
    fn send_return_observation(&self, packet: &Packet, original_deadline: Instant) -> Result<()> {
        // Ordinary upstream immutable observations; no queued send or new authority.
        if let Err(error) = crate::channel::require_time(original_deadline) {
            self.core.phase.revoke();
            return Err(error);
        }
        self.send(packet)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finished_return_observation_preserves_r_not_permission() {
        let p = Phases::new();
        p.step(0, 0, 72).unwrap();
        p.revoke();
        p.observe_return_completed(0).unwrap();
        assert!(p.revoked());
        assert_eq!(p.phase(0), 73);
        assert!(p.observe_return_completed(0).is_err());
    }
    #[test]
    fn return_cannot_skip_original_exact_phase() {
        for phase in 0..=255 {
            if phase == 72 {
                continue;
            }
            let p = Phases::new();
            if phase != 0 {
                p.step(0, 0, phase).unwrap();
            }
            assert!(p.observe_return_completed(0).is_err());
        }
    }
    #[test]
    fn exact_return_requires_entire_original_read_and_actual_prepared_commitments() {
        let r = crate::signer_return_data::tests::read();
        let mut p = crate::signer_return_data::tests::exact();
        let d = SignerReturnPreparedV1 {
            read_presentation_digest: r.presentation_digest.clone(),
            preview_digest: p.facts.preview_digest.clone(),
            reviewed_digest: p.facts.reviewed_digest.clone(),
            signature_set_digest: p.facts.signature_set_digest.clone(),
        };
        assert!(exact_matches(&p, &r, &d));
        p.facts.preview_digest = "aa".repeat(32);
        assert!(!exact_matches(&p, &r, &d));
    }
}
