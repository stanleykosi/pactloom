//! Closed post-wallet signing actions. Actual pinned-S kernels own all effects.
use super::activate::ActivateReview;
use super::signing::{FinancialSigningServingV1, SigningServiceLease};
use super::*;
use crate::signer_sign_data::*;
use crate::{SignerWalletObservePresentationV1, SignerWalletObservedV1, SignerWalletOriginalV1};
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
}
impl Presentation for SignerSignReadPresentationV1 {
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
    fn writer(&self) -> u64 {
        self.writer_session_ceiling_ms
    }
}
impl Presentation for SignerSignExactPresentationV1 {
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
        self.sign_ceiling_ms
    }
    fn times(&self) -> (u64, u64) {
        (self.facts.reviewed_at_ms, self.facts.expires_at_ms)
    }
    fn service(&self) -> u64 {
        self.service_ceiling_ms
    }
    fn writer(&self) -> u64 {
        self.writer_session_ceiling_ms
    }
}
struct Binding<P: Presentation> {
    activation: Arc<ActivateReview>,
    p: P,
    deadline: Instant,
    last_wall: AtomicU64,
}
impl<P: Presentation> Binding<P> {
    fn new(a: Arc<ActivateReview>, p: P) -> Result<Arc<Self>> {
        p.validate()?;
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
            last_wall: AtomicU64::new(state::wall_ms()?),
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
        if w < old || w < a || w >= b || Instant::now() >= self.deadline {
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
pub(super) struct SignSlots {
    pub(super) returning: super::returning::ReturnSlots,
    read: Slot<SignerSignReadPresentationV1, SignerSignPreparedV1>,
    exact: Slot<SignerSignExactPresentationV1, SignerSignCommittedV1>,
    terminal: bool,
}
fn same_original<P: Presentation>(
    p: &P,
    w: &SignerWalletObservePresentationV1,
    r: &SignerWalletObservedV1,
    service: u64,
    writer: u64,
) -> bool {
    p.original() == &w.facts.original
        && p.observed() == r
        && p.actor() == &w.actor
        && p.service() == service
        && p.writer() == writer
}
fn exact_matches(
    p: &SignerSignExactPresentationV1,
    r: &SignerSignReadPresentationV1,
    d: &SignerSignPreparedV1,
) -> bool {
    p.actor == r.actor
        && p.facts.original == r.facts.original
        && p.facts.observed == r.facts.observed
        && p.facts.original_read_presentation_digest == r.presentation_digest
        && d.read_presentation_digest == r.presentation_digest
        && p.facts.signing_terms_digest == d.signing_terms_digest
        && p.facts.active_receipt_digest == d.active_receipt_digest
        && p.facts.authenticated_history_digest == d.authenticated_history_digest
}
fn committed_matches(d: &SignerSignCommittedV1, p: &SignerSignExactPresentationV1) -> bool {
    d.sign_presentation_digest == p.presentation_digest
        && p.facts
            .expected_authorization_id()
            .is_ok_and(|id| id == d.authorization_id)
        && d.fixed_identity_digest == p.facts.original.fixed_identity_digest
}
pub struct SignerSignReadTicketV1 {
    binding: Arc<Binding<SignerSignReadPresentationV1>>,
    consumed: bool,
}
impl SignerSignReadTicketV1 {
    pub fn presentation(&self) -> &SignerSignReadPresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(62)
    }
}
impl Drop for SignerSignReadTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerSignReadOutboundV1 {
    binding: Arc<Binding<SignerSignReadPresentationV1>>,
    service: SigningServiceLease,
    consumed: bool,
}
impl Drop for SignerSignReadOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerSignReadFinalV1 {
    binding: Arc<Binding<SignerSignReadPresentationV1>>,
    consumed: bool,
}
impl SignerSignReadFinalV1 {
    pub fn presentation(&self) -> &SignerSignReadPresentationV1 {
        &self.binding.p
    }
    pub fn facts(&self) -> &SignerSignReadFactsV1 {
        &self.binding.p.facts
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(63)
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
impl Drop for SignerSignReadFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_sign_read(
        &self,
        mut ticket: SignerSignReadTicketV1,
        serving: &FinancialSigningServingV1,
    ) -> Result<SignerSignReadOutboundV1> {
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
        self.core.phase.step(b.slot(), 62, 63)?;
        ticket.consumed = true;
        Ok(SignerSignReadOutboundV1 {
            binding: Arc::clone(b),
            service,
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn try_send_sign_read(
        &mut self,
        mut out: SignerSignReadOutboundV1,
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
                .read;
            if !Arc::ptr_eq(&self.core, b.core())
                || s.phase != 62
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
            if self.core.phase.source_send_restricted(i, 63)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::SignReadFinal {
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
                    .read
                    .phase = 63;
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
pub struct SignerSignExactTicketV1 {
    binding: Arc<Binding<SignerSignExactPresentationV1>>,
    consumed: bool,
}
impl SignerSignExactTicketV1 {
    pub fn presentation(&self) -> &SignerSignExactPresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(65)
    }
}
impl Drop for SignerSignExactTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerSignExactOutboundV1 {
    binding: Arc<Binding<SignerSignExactPresentationV1>>,
    service: SigningServiceLease,
    consumed: bool,
}
impl Drop for SignerSignExactOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerSignExactFinalV1 {
    binding: Arc<Binding<SignerSignExactPresentationV1>>,
    consumed: bool,
    effects: AtomicU8,
}
impl SignerSignExactFinalV1 {
    pub fn presentation(&self) -> &SignerSignExactPresentationV1 {
        &self.binding.p
    }
    pub fn facts(&self) -> &SignerSignExactFactsV1 {
        &self.binding.p.facts
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(66)
    }
    pub fn original_sign_deadline(&self) -> Instant {
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
impl Drop for SignerSignExactFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_sign_exact(
        &self,
        mut ticket: SignerSignExactTicketV1,
        serving: &FinancialSigningServingV1,
    ) -> Result<SignerSignExactOutboundV1> {
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
        self.core.phase.step(b.slot(), 65, 66)?;
        ticket.consumed = true;
        Ok(SignerSignExactOutboundV1 {
            binding: Arc::clone(b),
            service,
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn try_send_sign_exact(
        &mut self,
        mut out: SignerSignExactOutboundV1,
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
                .exact;
            if !Arc::ptr_eq(&self.core, b.core())
                || s.phase != 65
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
            if self.core.phase.source_send_restricted(i, 66)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::SignExactFinal {
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
                    .exact
                    .phase = 66;
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
    pub fn offer_sign_read(
        &mut self,
        facts: SignerSignReadFactsV1,
        original_read: Instant,
    ) -> Result<SignerSignReadPresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        let (a, _) = self.activate.wallet_predecessor()?;
        let a = Arc::clone(a);
        let (w, r) = self.activate.wallet.sign_predecessor()?;
        let w = w.clone();
        let r = r.clone();
        a.wallet_bounds()?;
        if self.activate.wallet.sign.read.binding.is_some()
            || self.activate.wallet.sign.terminal
            || original_read > a.read.service.deadline
            || original_read > a.read.writer_deadline
            || original_read > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected("sign one original Read window"));
        }
        let mut p = SignerSignReadPresentationV1 {
            actor: a.wire.actor.clone(),
            facts,
            notice: READ_NOTICE.into(),
            challenge: state::nonce()?,
            source_ceiling_ms: a.wire.source_ceiling_ms,
            read_ceiling_ms: self.clocks.restrictive_offset(
                original_read,
                a.read.service.deadline.min(a.read.writer_deadline),
            )?,
            service_ceiling_ms: a.read.service.correlation().service_ceiling_ms,
            writer_session_ceiling_ms: self
                .clocks
                .restrictive_offset(a.read.writer_deadline, a.read.entry.original_source)?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        if !same_original(
            &p,
            &w,
            &r,
            p.service_ceiling_ms,
            p.writer_session_ceiling_ms,
        ) {
            return Err(rejected("sign actual wallet predecessor changed"));
        }
        let mut b = Binding::new(a, p.clone())?;
        Arc::get_mut(&mut b)
            .ok_or_else(|| rejected("sign binding escaped"))?
            .deadline = original_read;
        b.current(61)?;
        self.core.phase.step(self.target.index(), 61, 62)?;
        self.activate.wallet.sign.read = Slot {
            binding: Some(b),
            wire: Some(p.clone()),
            phase: 62,
            ..Default::default()
        };
        self.send_sign_observation(
            &Packet::SignReadDisplay {
                presentation: p.clone(),
            },
            original_read,
        )?;
        Ok(p)
    }
    pub fn offer_sign_exact(
        &mut self,
        mut read: SignerSignReadFinalV1,
        facts: SignerSignExactFactsV1,
        original_sign: Instant,
    ) -> Result<SignerSignExactPresentationV1> {
        read.check_current()?;
        facts.validate()?;
        let rb = Arc::clone(&read.binding);
        let s = &self.activate.wallet.sign;
        if !Arc::ptr_eq(&self.core, rb.core())
            || s.read.binding.as_ref().is_none_or(|b| !Arc::ptr_eq(b, &rb))
            || s.exact.binding.is_some()
            || s.terminal
            || original_sign > rb.activation.read.service.deadline
            || original_sign > rb.activation.read.writer_deadline
            || original_sign > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected("sign Exact original Read lineage/window"));
        }
        let d = SignerSignPreparedV1 {
            read_presentation_digest: rb.p.presentation_digest.clone(),
            signing_terms_digest: facts.signing_terms_digest.clone(),
            active_receipt_digest: facts.active_receipt_digest.clone(),
            authenticated_history_digest: facts.authenticated_history_digest.clone(),
        };
        d.validate()?;
        let mut p = SignerSignExactPresentationV1 {
            actor: rb.p.actor.clone(),
            facts,
            notice: EXACT_NOTICE.into(),
            challenge: state::nonce()?,
            source_ceiling_ms: rb.p.source_ceiling_ms,
            sign_ceiling_ms: self.clocks.restrictive_offset(
                original_sign,
                rb.activation
                    .read
                    .service
                    .deadline
                    .min(rb.activation.read.writer_deadline),
            )?,
            service_ceiling_ms: rb.p.service_ceiling_ms,
            writer_session_ceiling_ms: rb.p.writer_session_ceiling_ms,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        if !exact_matches(&p, &rb.p, &d) {
            return Err(rejected("sign Exact changed original prepared Read"));
        }
        let mut b = Binding::new(Arc::clone(&rb.activation), p.clone())?;
        Arc::get_mut(&mut b)
            .ok_or_else(|| rejected("sign Exact binding escaped"))?
            .deadline = original_sign;
        read.check_current()?;
        self.core.phase.step(self.target.index(), 63, 64)?;
        read.consumed = true;
        self.activate.wallet.sign.read.result = Some(d.clone());
        self.activate.wallet.sign.read.reported = true;
        self.activate.wallet.sign.read.phase = 64;
        self.send_sign_observation(
            &Packet::SignPrepared {
                role: self.target,
                data: d,
            },
            original_sign,
        )?;
        self.core.phase.step(self.target.index(), 64, 65)?;
        self.activate.wallet.sign.exact = Slot {
            binding: Some(b),
            wire: Some(p.clone()),
            phase: 65,
            ..Default::default()
        };
        self.send_sign_observation(
            &Packet::SignExactDisplay {
                presentation: p.clone(),
            },
            original_sign,
        )?;
        Ok(p)
    }
    pub fn report_sign_committed(&mut self, data: SignerSignCommittedV1) -> Result<()> {
        data.validate()?;
        let s = &mut self.activate.wallet.sign.exact;
        let b = s
            .binding
            .as_ref()
            .ok_or_else(|| rejected("sign result before Exact"))?;
        if s.reported
            || self.core.phase.phase(self.target.index()) != 67
            || !committed_matches(&data, &b.p)
        {
            return Err(rejected("sign result mismatch/replay"));
        }
        s.result = Some(data.clone());
        s.reported = true;
        s.phase = 67;
        let deadline = b.activation.read.entry.original_source;
        self.send_sign_observation(
            &Packet::SignCommitted {
                role: self.target,
                data,
            },
            deadline,
        )
    }
}
struct Attempt<'a> {
    core: &'a Core,
    effects: &'a AtomicU8,
    settled: bool,
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.effects.store(255, Ordering::Release);
            self.core.phase.revoke();
        }
    }
}
impl SignerSignExactFinalV1 {
    // Only pinned purpose-specific synchronous kernels call this private dispatcher.
    // All application/SQL/wallet locks precede entry; tx/secret work fully settles
    // inside closure. Already-entered work may settle after R; no rollback claim.
    fn execute(&self, index: u8, key: bool, effect: impl FnOnce() -> Result<()>) -> Result<()> {
        self.check_current()?;
        self.effects
            .compare_exchange(index, index + 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                self.binding.core().phase.revoke();
                rejected("sign effect skipped/repeated")
            })?;
        let core = self.binding.core();
        let mut attempt = Attempt {
            core,
            effects: &self.effects,
            settled: false,
        };
        let restriction = core
            .signer_restriction
            .as_ref()
            .ok_or_else(|| rejected("sign original restriction missing"))?;
        let run = || {
            self.check_current()?;
            effect()
        };
        if key {
            restriction.execute_sign_key_use(run)?;
        } else {
            restriction.execute_journal_publication(run)?;
        }
        self.effects.store(index + 2, Ordering::Release);
        attempt.settled = true;
        Ok(())
    }
    pub fn execute_sign_release_publication(
        &self,
        effect: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.execute(0, false, effect)
    }
    pub fn execute_sign_request_publication(
        &self,
        effect: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.execute(2, false, effect)
    }
    pub fn execute_sign_permit_publication(
        &self,
        effect: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.execute(4, false, effect)
    }
    pub fn execute_sign_started_publication(
        &self,
        effect: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.execute(6, false, effect)
    }
    pub fn execute_sign_key_use(&self, effect: impl FnOnce() -> Result<()>) -> Result<()> {
        self.execute(8, true, effect)
    }
    pub fn execute_sign_result_publication(
        &self,
        effect: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.execute(10, false, effect)
    }
    pub fn finish_sign(mut self) -> Result<()> {
        if self.effects.load(Ordering::Acquire) != 12
            || unsafe { libc::getpid() } != self.binding.core().owner_pid
            || unsafe { libc::geteuid() } != self.binding.core().owner_uid
        {
            return Err(rejected("sign result not completed by original actor"));
        }
        self.binding
            .core()
            .phase
            .observe_sign_committed(self.binding.slot())?;
        self.consumed = true;
        Ok(())
    }
}
impl SignerFinancialWorkflowOriginV1 {
    pub(in crate::financial_workflow_origin) fn receive_sign(
        &mut self,
        p: Packet,
    ) -> Result<SignerFinancialWorkflowRequestV1> {
        let role = p.target()?.ok_or_else(|| rejected("sign role"))?;
        if role != self.target || self.activate.wallet.sign.terminal {
            return Err(rejected("sign role/terminal"));
        }
        match p {
            Packet::SignReadFinal {
                presentation_digest,
                ..
            } => {
                let s = &mut self.activate.wallet.sign.read;
                let b = s
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("sign unsolicited Final"))?;
                if s.phase != 62 || presentation_digest != b.p.presentation_digest {
                    return Err(rejected("sign Final mismatch/replay"));
                }
                b.current(62)?;
                self.core.phase.step(role.index(), 62, 63)?;
                s.phase = 63;
                Ok(SignerFinancialWorkflowRequestV1::SignRead {
                    final_action: SignerSignReadFinalV1 {
                        binding: Arc::clone(b),
                        consumed: false,
                    },
                })
            }
            Packet::SignExactFinal {
                presentation_digest,
                ..
            } => {
                let s = &mut self.activate.wallet.sign.exact;
                let b = s
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("sign unsolicited Final"))?;
                if s.phase != 65 || presentation_digest != b.p.presentation_digest {
                    return Err(rejected("sign Final mismatch/replay"));
                }
                b.current(65)?;
                self.core.phase.step(role.index(), 65, 66)?;
                s.phase = 66;
                Ok(SignerFinancialWorkflowRequestV1::SignExact {
                    final_action: SignerSignExactFinalV1 {
                        binding: Arc::clone(b),
                        consumed: false,
                        effects: AtomicU8::new(0),
                    },
                })
            }
            _ => Err(rejected("wrong sign request")),
        }
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub(in crate::financial_workflow_origin) fn receive_sign_event(
        &mut self,
        p: Packet,
    ) -> Result<CoordinatorFinancialEventV1> {
        let role = p.target()?.ok_or_else(|| rejected("sign event role"))?;
        let i = role.index();
        let slot = self.slots[i]
            .as_mut()
            .ok_or_else(|| rejected("sign missing financial source"))?;
        let (a, _) = slot.activate.wallet_predecessor()?;
        let a = Arc::clone(a);
        let (w, r) = slot.activate.wallet.sign_predecessor()?;
        let w = w.clone();
        let r = r.clone();
        let s = &mut slot.activate.wallet.sign;
        if s.terminal {
            return Err(rejected("sign terminal"));
        }
        let service = a.read.service.correlation().service_ceiling_ms;
        let writer = self
            .clocks
            .restrictive_offset(a.read.writer_deadline, a.read.entry.original_source)?;
        match p {
            Packet::SignReadDisplay { presentation } => {
                if s.read.binding.is_some()
                    || !same_original(&presentation, &w, &r, service, writer)
                {
                    return Err(rejected("sign display predecessor mismatch"));
                }
                let b = Binding::new(a, presentation.clone())?;
                s.read.wire = Some(presentation);
                s.read.binding = Some(Arc::clone(&b));
                s.read.phase = 62;
                if !received_workflow_progress(&self.core.phase, i, 61, 62)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::SignReadDisplay(
                    SignerSignReadTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::SignExactDisplay { presentation } => {
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
                if !s.read.reported || s.read.phase != 64 || !exact_matches(&presentation, rp, d) {
                    return Err(rejected("Exact changed prepared source"));
                }
                let b = Binding::new(a, presentation.clone())?;
                s.exact.wire = Some(presentation);
                s.exact.binding = Some(Arc::clone(&b));
                s.exact.phase = 65;
                if !received_workflow_progress(&self.core.phase, i, 64, 65)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::SignExactDisplay(
                    SignerSignExactTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::SignPrepared { data, .. } => {
                data.validate()?;
                let t = &mut s.read;
                let p = t
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("sign prepared before Read"))?;
                if t.reported
                    || t.phase != 63
                    || data.read_presentation_digest != p.presentation_digest
                {
                    return Err(rejected("sign prepared mismatch/replay"));
                }
                t.result = Some(data.clone());
                t.reported = true;
                t.phase = 64;
                received_workflow_progress(&self.core.phase, i, 63, 64)?;
                Ok(CoordinatorFinancialEventV1::SignPrepared { role, data })
            }
            Packet::SignCommitted { data, .. } => {
                data.validate()?;
                let t = &mut s.exact;
                let p = t
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("sign committed before Exact"))?;
                if t.reported || t.phase != 66 || !committed_matches(&data, p) {
                    return Err(rejected("sign committed mismatch/replay"));
                }
                t.result = Some(data.clone());
                t.reported = true;
                t.phase = 67;
                received_workflow_progress(&self.core.phase, i, 66, 67)?;
                Ok(CoordinatorFinancialEventV1::SignCommitted { role, data })
            }
            Packet::SignFailed { data, .. } => {
                failure_matches(s, &data)?;
                s.terminal = true;
                self.core.phase.revoke();
                Ok(CoordinatorFinancialEventV1::SignFailed { role, data })
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
    if wall < *last || wall < a || wall >= b {
        return Err(rejected("sign relay action expired"));
    }
    *last = wall;
    Ok(())
}
impl HostFinancialWorkflowRelayV1 {
    pub(in crate::financial_workflow_origin) fn down_sign(&mut self, p: &Packet) -> Result<()> {
        if self.restricted {
            return Err(rejected("sign relay after R"));
        }
        let role = p.target()?.ok_or_else(|| rejected("sign relay role"))?;
        let slot = self.slots[role.index()]
            .as_mut()
            .ok_or_else(|| rejected("sign relay missing source"))?;
        let (_, _, service, writer) = slot.activate.wallet_predecessor()?;
        let deadline = service.deadline;
        let s = &mut slot.activate.wallet.sign;
        if s.terminal {
            return Err(rejected("sign relay terminal"));
        }
        match p {
            Packet::SignReadFinal {
                presentation_digest,
                ..
            } => {
                let t = &mut s.read;
                let p = t
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("sign relay before display"))?;
                if t.phase != 62 || presentation_digest != &p.presentation_digest {
                    return Err(rejected("sign relay Final mismatch/replay"));
                }
                relay_clock(p, deadline, writer, self.clocks, &mut slot.last_wall)?;
                t.phase = 63;
                Ok(())
            }
            Packet::SignExactFinal {
                presentation_digest,
                ..
            } => {
                let t = &mut s.exact;
                let p = t
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("sign relay before display"))?;
                if t.phase != 65 || presentation_digest != &p.presentation_digest {
                    return Err(rejected("sign relay Final mismatch/replay"));
                }
                relay_clock(p, deadline, writer, self.clocks, &mut slot.last_wall)?;
                t.phase = 66;
                Ok(())
            }
            _ => Err(rejected("wrong sign relay command")),
        }
    }
    pub(in crate::financial_workflow_origin) fn up_sign(
        &mut self,
        role: Target,
        p: &Packet,
    ) -> Result<bool> {
        let slot = self.slots[role.index()]
            .as_mut()
            .ok_or_else(|| rejected("sign relay missing source"))?;
        let (a, _, service, writer) = slot.activate.wallet_predecessor()?;
        let service_ceiling = service.correlation().service_ceiling_ms;
        let deadline = service.deadline;
        let writer_ceiling = self
            .clocks
            .restrictive_offset(writer, self.clocks.supervision())?;
        let (w, r) = slot.activate.wallet.sign_predecessor()?;
        let w = w.clone();
        let r = r.clone();
        let a = a.clone();
        let s = &mut slot.activate.wallet.sign;
        if s.terminal {
            return Err(rejected("sign relay terminal"));
        }
        match p {
            Packet::SignReadDisplay { presentation } => {
                if self.restricted {
                    return Ok(false);
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
                s.read.phase = 62;
                Ok(true)
            }
            Packet::SignExactDisplay { presentation } => {
                if self.restricted {
                    return Ok(false);
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
                if s.read.phase != 64 || !s.read.reported || !exact_matches(presentation, rp, d) {
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
                s.exact.phase = 65;
                Ok(true)
            }
            Packet::SignPrepared { data, .. } => {
                data.validate()?;
                let t = &mut s.read;
                let p = t
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("sign relay prepared before Read"))?;
                if t.reported
                    || t.phase != 63
                    || data.read_presentation_digest != p.presentation_digest
                {
                    return Err(rejected("sign relay prepared mismatch"));
                }
                t.result = Some(data.clone());
                t.reported = true;
                t.phase = 64;
                Ok(true)
            }
            Packet::SignCommitted { data, .. } => {
                data.validate()?;
                let t = &mut s.exact;
                let p = t
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("sign relay result before Exact"))?;
                if t.reported || t.phase != 66 || !committed_matches(data, p) {
                    return Err(rejected("sign relay result mismatch"));
                }
                t.result = Some(data.clone());
                t.reported = true;
                t.phase = 67;
                Ok(true)
            }
            Packet::SignFailed { data, .. } => {
                failure_matches(s, data)?;
                s.terminal = true;
                Ok(true)
            }
            _ => Err(rejected("wrong sign relay event")),
        }
    }
}
fn failure_matches(s: &SignSlots, d: &SignerSignFailureV1) -> Result<()> {
    d.validate()?;
    let ok = match d.stage {
        SignerSignFailureStageV1::ReadFailed => {
            s.read
                .wire
                .as_ref()
                .is_some_and(|p| p.presentation_digest == d.presentation_digest)
                && s.read.phase == 63
                && !s.read.reported
        }
        SignerSignFailureStageV1::SignUncertain => {
            s.exact
                .wire
                .as_ref()
                .is_some_and(|p| p.presentation_digest == d.presentation_digest)
                && s.exact.phase == 66
                && !s.exact.reported
        }
    };
    if s.terminal || !ok {
        return Err(rejected("sign failure mismatch/replay"));
    }
    Ok(())
}
impl SignerFinancialWorkflowOriginV1 {
    pub fn report_sign_failure(&mut self, data: SignerSignFailureV1) -> Result<()> {
        failure_matches(&self.activate.wallet.sign, &data)?;
        self.activate.wallet.sign.terminal = true;
        self.core.phase.revoke();
        self.send_sign_observation(
            &Packet::SignFailed {
                role: self.target,
                data,
            },
            self.clocks.supervision(),
        )
    }
}
impl SignSlots {
    pub(super) fn observe_active(&self, phase: u8) -> Result<()> {
        self.returning.observe_active(phase)?;
        if self.terminal {
            return Err(rejected("sign terminal"));
        }
        match phase {
            62 | 63 => self
                .read
                .binding
                .as_ref()
                .ok_or_else(|| rejected("sign missing Read"))?
                .bounds(),
            65 | 66 => self
                .exact
                .binding
                .as_ref()
                .ok_or_else(|| rejected("sign missing Exact"))?
                .bounds(),
            _ => Ok(()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_result_observation_preserves_r_and_cannot_repeat() {
        let p = Phases::new();
        p.step(0, 0, 66).unwrap();
        p.revoke();
        p.observe_sign_committed(0).unwrap();
        assert_eq!(p.phase(0), 67);
        assert!(p.revoked());
        assert!(p.observe_sign_committed(0).is_err());
    }
    #[test]
    fn no_other_phase_can_claim_actual_sign_result() {
        for phase in 0..=255 {
            if phase == 66 {
                continue;
            }
            let p = Phases::new();
            if phase != 0 {
                p.step(0, 0, phase).unwrap();
            }
            assert!(p.observe_sign_committed(0).is_err());
        }
    }
    #[test]
    fn exact_display_cannot_change_retained_read_or_prepared_receipt() {
        let r = crate::signer_sign_data::tests::read();
        let mut p = crate::signer_sign_data::tests::exact();
        let d = SignerSignPreparedV1 {
            read_presentation_digest: r.presentation_digest.clone(),
            signing_terms_digest: p.facts.signing_terms_digest.clone(),
            active_receipt_digest: p.facts.active_receipt_digest.clone(),
            authenticated_history_digest: p.facts.authenticated_history_digest.clone(),
        };
        assert!(exact_matches(&p, &r, &d));
        p.facts.original_read_presentation_digest = "ff".repeat(32);
        assert!(!exact_matches(&p, &r, &d));
    }
}

impl SignerFinancialWorkflowOriginV1 {
    /// These are immutable upstream displays/results, never authority-bearing
    /// packets. Preserve the supplied original cap before the existing one-shot
    /// MSG_DONTWAIT control send; C/H independently revalidate action ceilings
    /// before any native Final. There is no queued/waiting send or deadline renewal.
    fn send_sign_observation(&self, packet: &Packet, original_deadline: Instant) -> Result<()> {
        if let Err(error) = crate::channel::require_time(original_deadline) {
            self.core.phase.revoke();
            return Err(error);
        }
        self.send(packet)
    }
}

impl SignSlots {
    pub(super) fn return_predecessor(
        &self,
    ) -> Result<(&SignerSignExactPresentationV1, &SignerSignCommittedV1)> {
        if self.terminal || !self.exact.reported || self.exact.phase != 67 {
            return Err(rejected("Return before actual committed Sign"));
        }
        Ok((
            self.exact
                .wire
                .as_ref()
                .ok_or_else(|| rejected("Return missing Sign presentation"))?,
            self.exact
                .result
                .as_ref()
                .ok_or_else(|| rejected("Return missing actual Sign result"))?,
        ))
    }
}
