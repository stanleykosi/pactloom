//! Genuine post-Activate wallet actions, never native-grant conversions.
use super::activate::ActivateReview;
use super::signing::{FinancialSigningServingV1, SigningServiceLease};
use super::*;
use crate::signer_wallet_data::*;
use crate::{SignerActivateCommittedV1, SignerActivatePresentationV1};
use std::sync::atomic::AtomicU64;
use std::time::Duration;
#[derive(Default)]
pub(super) struct WalletSlots {
    pub(super) sign: super::sign::SignSlots,
    prepare: PrepareSlot,
    observe: ObserveSlot,
    terminal: bool,
}
#[derive(Default)]
struct PrepareSlot {
    binding: Option<Arc<PrepareBinding>>,
    wire: Option<SignerWalletPreparePresentationV1>,
    result: Option<SignerWalletPreparedV1>,
    phase: u8,
    reported: bool,
}
struct PrepareBinding {
    activation: Arc<ActivateReview>,
    p: SignerWalletPreparePresentationV1,
    deadline: Instant,
    last_wall: AtomicU64,
}
impl PrepareBinding {
    fn new(
        activation: Arc<ActivateReview>,
        p: SignerWalletPreparePresentationV1,
    ) -> Result<Arc<Self>> {
        p.validate()?;
        activation.wallet_bounds()?;
        let now = Instant::now();
        let deadline = activation
            .read
            .entry
            .clocks
            .restrict_received(
                PROFILE,
                p.prepare_ceiling_ms,
                activation
                    .read
                    .writer_deadline
                    .min(activation.read.writer_wall_deadline)
                    .min(activation.read.service.deadline),
                now,
            )?
            .min(wall_ceiling(
                now,
                state::wall_ms()?,
                p.facts.reviewed_at_ms,
                p.facts.expires_at_ms,
            )?);
        let b = Arc::new(Self {
            activation,
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
        let wall = state::wall_ms()?;
        let old = self.last_wall.fetch_max(wall, Ordering::AcqRel);
        if wall < old
            || wall < self.p.facts.reviewed_at_ms
            || wall >= self.p.facts.expires_at_ms
            || Instant::now() >= self.deadline
        {
            return Err(rejected("wallet original action expired"));
        }
        Ok(())
    }
    fn current(&self, phase: u8) -> Result<()> {
        self.bounds()?;
        self.core().check_action_restrictions()?;
        if self.core().phase.phase(self.slot()) != phase {
            return Err(rejected("wallet consumed/reordered"));
        }
        Ok(())
    }
}
pub struct SignerWalletPrepareTicketV1 {
    binding: Arc<PrepareBinding>,
    consumed: bool,
}
impl SignerWalletPrepareTicketV1 {
    pub fn presentation(&self) -> &SignerWalletPreparePresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(56)
    }
}
impl Drop for SignerWalletPrepareTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerWalletPrepareOutboundV1 {
    binding: Arc<PrepareBinding>,
    service: SigningServiceLease,
    consumed: bool,
}
impl Drop for SignerWalletPrepareOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerWalletPrepareFinalV1 {
    binding: Arc<PrepareBinding>,
    consumed: bool,
}
impl SignerWalletPrepareFinalV1 {
    pub fn presentation(&self) -> &SignerWalletPreparePresentationV1 {
        &self.binding.p
    }
    pub fn facts(&self) -> &SignerWalletPrepareFactsV1 {
        &self.binding.p.facts
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(57)
    }
    pub fn original_prepare_deadline(&self) -> Instant {
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
    pub fn finish_prepare(mut self) -> Result<()> {
        self.check_current()?;
        self.binding
            .core()
            .phase
            .step(self.binding.slot(), 57, 58)?;
        self.consumed = true;
        Ok(())
    }
}
impl Drop for SignerWalletPrepareFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
fn prepare_matches(
    p: &SignerWalletPreparePresentationV1,
    activation: &SignerActivatePresentationV1,
    committed: &SignerActivateCommittedV1,
    service_ceiling: u64,
    writer_ceiling: u64,
    prepared: Option<&SignerWalletPreparedV1>,
) -> bool {
    p.actor == activation.actor
        && p.source_ceiling_ms == activation.source_ceiling_ms
        && p.facts.original.activation == *activation
        && p.facts.original.activated == *committed
        && p.service_ceiling_ms == service_ceiling
        && p.writer_session_ceiling_ms == writer_ceiling
}
impl SignerFinancialWorkflowOriginV1 {
    pub fn offer_wallet_prepare(
        &mut self,
        facts: SignerWalletPrepareFactsV1,
        original_prepare: Instant,
    ) -> Result<SignerWalletPreparePresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        let (activation, committed) = self.activate.wallet_predecessor()?;
        let activation = Arc::clone(activation);
        let committed = committed.clone();
        activation.wallet_bounds()?;
        let original = original_prepare;
        if self.activate.wallet.terminal
            || self.activate.wallet.prepare.binding.is_some()
            || original > activation.read.service.deadline
            || original > activation.read.writer_deadline
            || original > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected("wallet one original action window"));
        }
        let mut p = SignerWalletPreparePresentationV1 {
            actor: activation.wire.actor.clone(),
            facts,
            notice: PREPARE_NOTICE.into(),
            challenge: state::nonce()?,
            source_ceiling_ms: activation.wire.source_ceiling_ms,
            service_ceiling_ms: activation.read.service.correlation().service_ceiling_ms,
            writer_session_ceiling_ms: self.clocks.restrictive_offset(
                activation.read.writer_deadline,
                activation.read.entry.original_source,
            )?,
            prepare_ceiling_ms: self.clocks.restrictive_offset(
                original,
                activation
                    .read
                    .service
                    .deadline
                    .min(activation.read.writer_deadline),
            )?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        if !prepare_matches(
            &p,
            &activation.wire,
            &committed,
            p.service_ceiling_ms,
            p.writer_session_ceiling_ms,
            self.activate.wallet.prepare.result.as_ref(),
        ) {
            return Err(rejected("wallet actual original mismatch"));
        }
        let mut b = PrepareBinding::new(activation, p.clone())?;
        Arc::get_mut(&mut b)
            .ok_or_else(|| rejected("new wallet binding shared"))?
            .deadline = original;
        b.bounds()?;
        self.core.phase.step(self.target.index(), 55, 56)?;
        self.activate.wallet.prepare.binding = Some(b);
        self.activate.wallet.prepare.wire = Some(p.clone());
        self.activate.wallet.prepare.phase = 56;
        self.send(&Packet::WalletPrepareDisplay {
            presentation: p.clone(),
        })?;
        Ok(p)
    }
    pub fn report_wallet_prepared(&mut self, data: SignerWalletPreparedV1) -> Result<()> {
        data.validate()?;
        let slot = &mut self.activate.wallet.prepare;
        let b = slot
            .binding
            .as_ref()
            .ok_or_else(|| rejected("wallet result before offer"))?;
        if slot.reported
            || slot.phase != 57
            || self.core.phase.phase(self.target.index()) != 58
            || !prepared_matches(&data, &b.p)
        {
            return Err(rejected("wallet actual result mismatch/replay"));
        }
        slot.result = Some(data.clone());
        slot.reported = true;
        slot.phase = 58;
        self.send(&Packet::WalletPrepared {
            role: self.target,
            data,
        })
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_wallet_prepare(
        &self,
        mut ticket: SignerWalletPrepareTicketV1,
        serving: &FinancialSigningServingV1,
    ) -> Result<SignerWalletPrepareOutboundV1> {
        let b = &ticket.binding;
        if !Arc::ptr_eq(&self.core, b.core()) {
            self.revoke();
            return Err(rejected("wallet foreign native Core"));
        }
        serving.matches_acquire(&self.core, &b.activation.read.acquired_presentation)?;
        let service = serving.retain()?;
        b.activation
            .read
            .service
            .require_same(&service.correlation())?;
        ticket.check_current()?;
        service.check()?;
        self.core.phase.step(b.slot(), 56, 57)?;
        ticket.consumed = true;
        Ok(SignerWalletPrepareOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            service,
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn try_send_wallet_prepare(
        &mut self,
        mut out: SignerWalletPrepareOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = Arc::clone(&out.binding);
        let i = b.slot();
        let result = (|| {
            let slot = self.slots[i]
                .as_ref()
                .ok_or_else(|| rejected("wallet outbound before financial source"))?;
            let slot = &slot.activate.wallet.prepare;
            if !Arc::ptr_eq(&self.core, b.core())
                || slot.phase != 56
                || slot.binding.as_ref().is_none_or(|v| !Arc::ptr_eq(v, &b))
            {
                return Err(rejected("wallet outbound foreign/reused"));
            }
            b.bounds()?;
            out.service.check()?;
            b.activation
                .read
                .service
                .require_same(&out.service.correlation())?;
            if self.core.phase.source_send_restricted(i, 57)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::WalletPrepareFinal {
                    role: b.p.actor.signer_role,
                    presentation_digest: b.p.presentation_digest.clone(),
                },
                b.deadline,
            )?;
            if r == FinancialSendProgressV1::Sent {
                self.slots[i]
                    .as_mut()
                    .ok_or_else(|| rejected("wallet slot lost"))?
                    .activate
                    .wallet
                    .prepare
                    .phase = 57;
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
#[derive(Default)]
struct ObserveSlot {
    binding: Option<Arc<ObserveBinding>>,
    wire: Option<SignerWalletObservePresentationV1>,
    result: Option<SignerWalletObservedV1>,
    phase: u8,
    reported: bool,
}
struct ObserveBinding {
    activation: Arc<ActivateReview>,
    p: SignerWalletObservePresentationV1,
    deadline: Instant,
    last_wall: AtomicU64,
}
impl ObserveBinding {
    fn new(
        activation: Arc<ActivateReview>,
        p: SignerWalletObservePresentationV1,
    ) -> Result<Arc<Self>> {
        p.validate()?;
        activation.wallet_bounds()?;
        let now = Instant::now();
        let deadline = activation
            .read
            .entry
            .clocks
            .restrict_received(
                PROFILE,
                p.observe_ceiling_ms,
                activation
                    .read
                    .writer_deadline
                    .min(activation.read.writer_wall_deadline)
                    .min(activation.read.service.deadline),
                now,
            )?
            .min(wall_ceiling(
                now,
                state::wall_ms()?,
                p.facts.reviewed_at_ms,
                p.facts.expires_at_ms,
            )?);
        let b = Arc::new(Self {
            activation,
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
        let wall = state::wall_ms()?;
        let old = self.last_wall.fetch_max(wall, Ordering::AcqRel);
        if wall < old
            || wall < self.p.facts.reviewed_at_ms
            || wall >= self.p.facts.expires_at_ms
            || Instant::now() >= self.deadline
        {
            return Err(rejected("wallet original action expired"));
        }
        Ok(())
    }
    fn current(&self, phase: u8) -> Result<()> {
        self.bounds()?;
        self.core().check_action_restrictions()?;
        if self.core().phase.phase(self.slot()) != phase {
            return Err(rejected("wallet consumed/reordered"));
        }
        Ok(())
    }
}
pub struct SignerWalletObserveTicketV1 {
    binding: Arc<ObserveBinding>,
    consumed: bool,
}
impl SignerWalletObserveTicketV1 {
    pub fn presentation(&self) -> &SignerWalletObservePresentationV1 {
        &self.binding.p
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(59)
    }
}
impl Drop for SignerWalletObserveTicketV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerWalletObserveOutboundV1 {
    binding: Arc<ObserveBinding>,
    service: SigningServiceLease,
    consumed: bool,
}
impl Drop for SignerWalletObserveOutboundV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
pub struct SignerWalletObserveFinalV1 {
    binding: Arc<ObserveBinding>,
    consumed: bool,
    effect: AtomicU8,
}
impl SignerWalletObserveFinalV1 {
    pub fn presentation(&self) -> &SignerWalletObservePresentationV1 {
        &self.binding.p
    }
    pub fn facts(&self) -> &SignerWalletObserveFactsV1 {
        &self.binding.p.facts
    }
    pub fn check_current(&self) -> Result<()> {
        self.binding.current(60)
    }
    pub fn original_observe_deadline(&self) -> Instant {
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
    /// Enter only the one actual synchronous FVK import with validated local locks
    /// already held. No network sync/await/queue may span this gate. Entered import
    /// may settle after R; any subsequent failure remains uncertain, never retry.
    pub fn execute_wallet_observe_import(&self, import: impl FnOnce() -> Result<()>) -> Result<()> {
        self.check_current()?;
        self.effect
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                self.binding.core().phase.revoke();
                rejected("wallet import one-use")
            })?;
        let core = self.binding.core();
        let mut attempt = WalletImportAttempt {
            core,
            effect: &self.effect,
            settled: false,
        };
        let restriction = core
            .signer_restriction
            .as_ref()
            .ok_or_else(|| rejected("wallet missing original restriction"))?;
        restriction.execute_wallet_observe_import(|| {
            self.check_current()?;
            import()
        })?;
        self.effect.store(2, Ordering::Release);
        attempt.settled = true;
        Ok(())
    }
    pub fn finish_observe(mut self) -> Result<()> {
        self.check_current()?;
        if self.effect.load(Ordering::Acquire) != 2 {
            return Err(rejected("wallet Observe lacks completed actual import"));
        }
        self.binding
            .core()
            .phase
            .step(self.binding.slot(), 60, 61)?;
        self.consumed = true;
        Ok(())
    }
}
impl Drop for SignerWalletObserveFinalV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.binding.core().phase.revoke();
        }
    }
}
fn observe_matches(
    p: &SignerWalletObservePresentationV1,
    activation: &SignerActivatePresentationV1,
    committed: &SignerActivateCommittedV1,
    service_ceiling: u64,
    writer_ceiling: u64,
    prepared: Option<&SignerWalletPreparedV1>,
) -> bool {
    p.actor == activation.actor
        && p.source_ceiling_ms == activation.source_ceiling_ms
        && p.facts.original.activation == *activation
        && p.facts.original.activated == *committed
        && p.service_ceiling_ms == service_ceiling
        && p.writer_session_ceiling_ms == writer_ceiling
        && prepared.is_some_and(|d| {
            d.prepare_presentation_digest == p.facts.prepare_presentation_digest
                && d.activation_presentation_digest == activation.presentation_digest
                && d.fixed_identity_digest == p.facts.original.fixed_identity_digest
                && d.configuration_digest == p.facts.original.configuration_digest
                && d.wallet_review_digest == p.facts.wallet_review_digest
        })
}
impl SignerFinancialWorkflowOriginV1 {
    pub fn offer_wallet_observe(
        &mut self,
        facts: SignerWalletObserveFactsV1,
        original_observe: Instant,
    ) -> Result<SignerWalletObservePresentationV1> {
        self.core.check_action_restrictions()?;
        facts.validate()?;
        let (activation, committed) = self.activate.wallet_predecessor()?;
        let activation = Arc::clone(activation);
        let committed = committed.clone();
        activation.wallet_bounds()?;
        let original = original_observe;
        if self.activate.wallet.terminal
            || self.activate.wallet.observe.binding.is_some()
            || original > activation.read.service.deadline
            || original > activation.read.writer_deadline
            || original > Instant::now() + Duration::from_secs(120)
        {
            return Err(rejected("wallet one original action window"));
        }
        if !self.activate.wallet.prepare.reported {
            return Err(rejected("Observe before actual wallet preparation"));
        }
        let mut p = SignerWalletObservePresentationV1 {
            actor: activation.wire.actor.clone(),
            facts,
            notice: OBSERVE_NOTICE.into(),
            challenge: state::nonce()?,
            source_ceiling_ms: activation.wire.source_ceiling_ms,
            service_ceiling_ms: activation.read.service.correlation().service_ceiling_ms,
            writer_session_ceiling_ms: self.clocks.restrictive_offset(
                activation.read.writer_deadline,
                activation.read.entry.original_source,
            )?,
            observe_ceiling_ms: self.clocks.restrictive_offset(
                original,
                activation
                    .read
                    .service
                    .deadline
                    .min(activation.read.writer_deadline),
            )?,
            presentation_digest: String::new(),
        };
        p.presentation_digest = p.calculate_presentation_digest()?;
        if !observe_matches(
            &p,
            &activation.wire,
            &committed,
            p.service_ceiling_ms,
            p.writer_session_ceiling_ms,
            self.activate.wallet.prepare.result.as_ref(),
        ) {
            return Err(rejected("wallet actual original mismatch"));
        }
        let mut b = ObserveBinding::new(activation, p.clone())?;
        Arc::get_mut(&mut b)
            .ok_or_else(|| rejected("new wallet binding shared"))?
            .deadline = original;
        b.bounds()?;
        self.core.phase.step(self.target.index(), 58, 59)?;
        self.activate.wallet.observe.binding = Some(b);
        self.activate.wallet.observe.wire = Some(p.clone());
        self.activate.wallet.observe.phase = 59;
        self.send(&Packet::WalletObserveDisplay {
            presentation: p.clone(),
        })?;
        Ok(p)
    }
    pub fn report_wallet_observed(&mut self, data: SignerWalletObservedV1) -> Result<()> {
        data.validate()?;
        let slot = &mut self.activate.wallet.observe;
        let b = slot
            .binding
            .as_ref()
            .ok_or_else(|| rejected("wallet result before offer"))?;
        if slot.reported
            || slot.phase != 60
            || self.core.phase.phase(self.target.index()) != 61
            || !observed_matches(&data, &b.p)
        {
            return Err(rejected("wallet actual result mismatch/replay"));
        }
        slot.result = Some(data.clone());
        slot.reported = true;
        slot.phase = 61;
        self.send(&Packet::WalletObserved {
            role: self.target,
            data,
        })
    }
}
impl CoordinatorFinancialNativeV1 {
    pub fn admit_wallet_observe(
        &self,
        mut ticket: SignerWalletObserveTicketV1,
        serving: &FinancialSigningServingV1,
    ) -> Result<SignerWalletObserveOutboundV1> {
        let b = &ticket.binding;
        if !Arc::ptr_eq(&self.core, b.core()) {
            self.revoke();
            return Err(rejected("wallet foreign native Core"));
        }
        serving.matches_acquire(&self.core, &b.activation.read.acquired_presentation)?;
        let service = serving.retain()?;
        b.activation
            .read
            .service
            .require_same(&service.correlation())?;
        ticket.check_current()?;
        service.check()?;
        self.core.phase.step(b.slot(), 59, 60)?;
        ticket.consumed = true;
        Ok(SignerWalletObserveOutboundV1 {
            binding: Arc::clone(&ticket.binding),
            service,
            consumed: false,
        })
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub fn try_send_wallet_observe(
        &mut self,
        mut out: SignerWalletObserveOutboundV1,
    ) -> Result<FinancialSendProgressV1> {
        let b = Arc::clone(&out.binding);
        let i = b.slot();
        let result = (|| {
            let slot = self.slots[i]
                .as_ref()
                .ok_or_else(|| rejected("wallet outbound before financial source"))?;
            let slot = &slot.activate.wallet.observe;
            if !Arc::ptr_eq(&self.core, b.core())
                || slot.phase != 59
                || slot.binding.as_ref().is_none_or(|v| !Arc::ptr_eq(v, &b))
            {
                return Err(rejected("wallet outbound foreign/reused"));
            }
            b.bounds()?;
            out.service.check()?;
            b.activation
                .read
                .service
                .require_same(&out.service.correlation())?;
            if self.core.phase.source_send_restricted(i, 60)? {
                return Ok(FinancialSendProgressV1::Restricted);
            }
            let r = self.send_positive(
                &Packet::WalletObserveFinal {
                    role: b.p.actor.signer_role,
                    presentation_digest: b.p.presentation_digest.clone(),
                },
                b.deadline,
            )?;
            if r == FinancialSendProgressV1::Sent {
                self.slots[i]
                    .as_mut()
                    .ok_or_else(|| rejected("wallet slot lost"))?
                    .activate
                    .wallet
                    .observe
                    .phase = 60;
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
fn prepared_matches(d: &SignerWalletPreparedV1, p: &SignerWalletPreparePresentationV1) -> bool {
    d.validate().is_ok()
        && d.prepare_presentation_digest == p.presentation_digest
        && d.activation_presentation_digest == p.facts.original.activation.presentation_digest
        && d.fixed_identity_digest == p.facts.original.fixed_identity_digest
        && d.configuration_digest == p.facts.original.configuration_digest
}
fn observed_matches(d: &SignerWalletObservedV1, p: &SignerWalletObservePresentationV1) -> bool {
    d.validate().is_ok()
        && d.observe_presentation_digest == p.presentation_digest
        && d.prepare_presentation_digest == p.facts.prepare_presentation_digest
        && d.activation_presentation_digest == p.facts.original.activation.presentation_digest
        && d.fixed_identity_digest == p.facts.original.fixed_identity_digest
        && d.configuration_digest == p.facts.original.configuration_digest
        && d.wallet_review_digest == p.facts.wallet_review_digest
}
struct WalletImportAttempt<'a> {
    core: &'a Core,
    effect: &'a AtomicU8,
    settled: bool,
}
impl Drop for WalletImportAttempt<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.effect.store(3, Ordering::Release);
            self.core.phase.revoke();
        }
    }
}
impl SignerFinancialWorkflowOriginV1 {
    pub(in crate::financial_workflow_origin) fn receive_wallet(
        &mut self,
        p: Packet,
    ) -> Result<SignerFinancialWorkflowRequestV1> {
        let role = p.target()?.ok_or_else(|| rejected("wallet role"))?;
        if role != self.target || self.activate.wallet.terminal {
            return Err(rejected("wallet original role or terminal"));
        }
        match p {
            Packet::WalletPrepareFinal {
                presentation_digest,
                ..
            } => {
                let slot = &mut self.activate.wallet.prepare;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("wallet Final unsolicited"))?;
                if slot.phase != 56 || presentation_digest != b.p.presentation_digest {
                    return Err(rejected("wallet Final mismatch/replay"));
                }
                b.current(56)?;
                self.core.phase.step(role.index(), 56, 57)?;
                slot.phase = 57;
                Ok(SignerFinancialWorkflowRequestV1::WalletPrepare {
                    final_action: SignerWalletPrepareFinalV1 {
                        binding: Arc::clone(b),
                        consumed: false,
                    },
                })
            }
            Packet::WalletObserveFinal {
                presentation_digest,
                ..
            } => {
                let slot = &mut self.activate.wallet.observe;
                let b = slot
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("wallet Final unsolicited"))?;
                if slot.phase != 59 || presentation_digest != b.p.presentation_digest {
                    return Err(rejected("wallet Final mismatch/replay"));
                }
                b.current(59)?;
                self.core.phase.step(role.index(), 59, 60)?;
                slot.phase = 60;
                Ok(SignerFinancialWorkflowRequestV1::WalletObserve {
                    final_action: SignerWalletObserveFinalV1 {
                        binding: Arc::clone(b),
                        consumed: false,
                        effect: AtomicU8::new(0),
                    },
                })
            }
            _ => Err(rejected("wrong wallet request")),
        }
    }
}
impl CoordinatorFinancialEndpointV1 {
    pub(in crate::financial_workflow_origin) fn receive_wallet_event(
        &mut self,
        p: Packet,
    ) -> Result<CoordinatorFinancialEventV1> {
        let role = p.target()?.ok_or_else(|| rejected("wallet event role"))?;
        let i = role.index();
        let slot = self.slots[i]
            .as_mut()
            .ok_or_else(|| rejected("wallet event before financial source"))?;
        let (activation, committed) = slot.activate.wallet_predecessor()?;
        let activation = Arc::clone(activation);
        let committed = committed.clone();
        if slot.activate.wallet.terminal {
            return Err(rejected("wallet event after terminal"));
        }
        let writer = self.clocks.restrictive_offset(
            activation.read.writer_deadline,
            activation.read.entry.original_source,
        )?;
        let service = activation.read.service.correlation().service_ceiling_ms;
        match p {
            Packet::WalletPrepareDisplay { presentation } => {
                if slot.activate.wallet.prepare.binding.is_some()
                    || !prepare_matches(
                        &presentation,
                        &activation.wire,
                        &committed,
                        service,
                        writer,
                        slot.activate.wallet.prepare.result.as_ref(),
                    )
                {
                    return Err(rejected("wallet display predecessor mismatch"));
                }
                let b = PrepareBinding::new(activation, presentation.clone())?;
                slot.activate.wallet.prepare.wire = Some(presentation);
                slot.activate.wallet.prepare.binding = Some(Arc::clone(&b));
                slot.activate.wallet.prepare.phase = 56;
                if !received_workflow_progress(&self.core.phase, i, 55, 56)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::WalletPrepareDisplay(
                    SignerWalletPrepareTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::WalletPrepared { data, .. } => {
                data.validate()?;
                let w = &mut slot.activate.wallet.prepare;
                let b = w
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("wallet result before review"))?;
                if w.reported || w.phase != 57 || !prepared_matches(&data, &b.p) {
                    return Err(rejected("wallet actual result mismatch/replay"));
                }
                w.result = Some(data.clone());
                w.reported = true;
                w.phase = 58;
                received_workflow_progress(&self.core.phase, i, 57, 58)?;
                Ok(CoordinatorFinancialEventV1::WalletPrepared { role, data })
            }
            Packet::WalletObserveDisplay { presentation } => {
                if slot.activate.wallet.observe.binding.is_some()
                    || !observe_matches(
                        &presentation,
                        &activation.wire,
                        &committed,
                        service,
                        writer,
                        slot.activate.wallet.prepare.result.as_ref(),
                    )
                    || !slot.activate.wallet.prepare.reported
                {
                    return Err(rejected("wallet display predecessor mismatch"));
                }
                let b = ObserveBinding::new(activation, presentation.clone())?;
                slot.activate.wallet.observe.wire = Some(presentation);
                slot.activate.wallet.observe.binding = Some(Arc::clone(&b));
                slot.activate.wallet.observe.phase = 59;
                if !received_workflow_progress(&self.core.phase, i, 58, 59)? {
                    return Ok(CoordinatorFinancialEventV1::Restricted(role));
                }
                Ok(CoordinatorFinancialEventV1::WalletObserveDisplay(
                    SignerWalletObserveTicketV1 {
                        binding: b,
                        consumed: false,
                    },
                ))
            }
            Packet::WalletObserved { data, .. } => {
                data.validate()?;
                let w = &mut slot.activate.wallet.observe;
                let b = w
                    .binding
                    .as_ref()
                    .ok_or_else(|| rejected("wallet result before review"))?;
                if w.reported || w.phase != 60 || !observed_matches(&data, &b.p) {
                    return Err(rejected("wallet actual result mismatch/replay"));
                }
                w.result = Some(data.clone());
                w.reported = true;
                w.phase = 61;
                received_workflow_progress(&self.core.phase, i, 60, 61)?;
                Ok(CoordinatorFinancialEventV1::WalletObserved { role, data })
            }
            Packet::WalletFailed { data, .. } => {
                data.validate()?;
                slot.activate.wallet.validate_failure(&data)?;
                slot.activate.wallet.terminal = true;
                self.core.phase.revoke();
                Ok(CoordinatorFinancialEventV1::WalletFailed { role, data })
            }
            _ => Err(rejected("wrong wallet event")),
        }
    }
}
fn wallet_relay_clock(
    review: u64,
    start: u64,
    end: u64,
    service: &super::writer_acquire::ReceivedSigning,
    writer: Instant,
    writer_wall: Instant,
    clocks: FullWorkflowClocksV1,
    last: &mut u64,
) -> Result<()> {
    service.check()?;
    crate::channel::require_time(writer.min(writer_wall))?;
    clocks.restrict_received(
        PROFILE,
        review,
        writer.min(writer_wall).min(service.deadline),
        Instant::now(),
    )?;
    let wall = state::wall_ms()?;
    if wall < *last || wall < start || wall >= end {
        return Err(rejected("wallet original relay window"));
    }
    *last = wall;
    Ok(())
}
impl HostFinancialWorkflowRelayV1 {
    pub(in crate::financial_workflow_origin) fn down_wallet(&mut self, p: &Packet) -> Result<()> {
        if self.restricted {
            return Err(rejected("wallet command after R"));
        }
        let role = p.target()?.ok_or_else(|| rejected("wallet relay role"))?;
        let slot = self.slots[role.index()]
            .as_mut()
            .ok_or_else(|| rejected("wallet relay before source"))?;
        if slot.activate.wallet.terminal {
            return Err(rejected("wallet terminal relay"));
        }
        let (_, _, service, writer) = slot.activate.wallet_predecessor()?;
        let writer_wall = slot.activate.retained_wall_deadline()?;
        match p {
            Packet::WalletPrepareFinal {
                presentation_digest,
                ..
            } => {
                let w = &slot.activate.wallet.prepare;
                let p = w
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("wallet relay Final before display"))?;
                if w.phase != 56 || presentation_digest != &p.presentation_digest {
                    return Err(rejected("wallet relay Final mismatch/replay"));
                }
                wallet_relay_clock(
                    p.prepare_ceiling_ms,
                    p.facts.reviewed_at_ms,
                    p.facts.expires_at_ms,
                    service,
                    writer,
                    writer_wall,
                    self.clocks,
                    &mut slot.last_wall,
                )?;
                slot.activate.wallet.prepare.phase = 57;
                Ok(())
            }
            Packet::WalletObserveFinal {
                presentation_digest,
                ..
            } => {
                let w = &slot.activate.wallet.observe;
                let p = w
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("wallet relay Final before display"))?;
                if w.phase != 59 || presentation_digest != &p.presentation_digest {
                    return Err(rejected("wallet relay Final mismatch/replay"));
                }
                wallet_relay_clock(
                    p.observe_ceiling_ms,
                    p.facts.reviewed_at_ms,
                    p.facts.expires_at_ms,
                    service,
                    writer,
                    writer_wall,
                    self.clocks,
                    &mut slot.last_wall,
                )?;
                slot.activate.wallet.observe.phase = 60;
                Ok(())
            }
            _ => Err(rejected("wrong wallet relay command")),
        }
    }
    pub(in crate::financial_workflow_origin) fn up_wallet(
        &mut self,
        role: Target,
        p: &Packet,
    ) -> Result<bool> {
        let slot = self.slots[role.index()]
            .as_mut()
            .ok_or_else(|| rejected("wallet relay event before source"))?;
        let (activation, committed, service, writer) = slot.activate.wallet_predecessor()?;
        let writer_wall = slot.activate.retained_wall_deadline()?;
        if slot.activate.wallet.terminal {
            return Err(rejected("wallet relay terminal"));
        }
        let writer_ceiling = self
            .clocks
            .restrictive_offset(writer, self.clocks.supervision())?;
        match p {
            Packet::WalletPrepareDisplay { presentation } => {
                presentation.validate()?;
                if slot.activate.wallet.prepare.wire.is_some()
                    || !prepare_matches(
                        presentation,
                        activation,
                        committed,
                        service.correlation().service_ceiling_ms,
                        writer_ceiling,
                        slot.activate.wallet.prepare.result.as_ref(),
                    )
                {
                    return Err(rejected("wallet relay original display mismatch"));
                }
                if !self.restricted {
                    wallet_relay_clock(
                        presentation.prepare_ceiling_ms,
                        presentation.facts.reviewed_at_ms,
                        presentation.facts.expires_at_ms,
                        service,
                        writer,
                        writer_wall,
                        self.clocks,
                        &mut slot.last_wall,
                    )?;
                }
                slot.activate.wallet.prepare.wire = Some(presentation.clone());
                slot.activate.wallet.prepare.phase = 56;
                Ok(!self.restricted)
            }
            Packet::WalletPrepared { data, .. } => {
                data.validate()?;
                let w = &mut slot.activate.wallet.prepare;
                let p = w
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("wallet relay result before offer"))?;
                if w.reported || w.phase != 57 || !prepared_matches(data, p) {
                    return Err(rejected("wallet relay actual result mismatch/replay"));
                }
                w.result = Some(data.clone());
                w.reported = true;
                w.phase = 58;
                Ok(true)
            }
            Packet::WalletObserveDisplay { presentation } => {
                presentation.validate()?;
                if slot.activate.wallet.observe.wire.is_some()
                    || !observe_matches(
                        presentation,
                        activation,
                        committed,
                        service.correlation().service_ceiling_ms,
                        writer_ceiling,
                        slot.activate.wallet.prepare.result.as_ref(),
                    )
                    || !slot.activate.wallet.prepare.reported
                {
                    return Err(rejected("wallet relay original display mismatch"));
                }
                if !self.restricted {
                    wallet_relay_clock(
                        presentation.observe_ceiling_ms,
                        presentation.facts.reviewed_at_ms,
                        presentation.facts.expires_at_ms,
                        service,
                        writer,
                        writer_wall,
                        self.clocks,
                        &mut slot.last_wall,
                    )?;
                }
                slot.activate.wallet.observe.wire = Some(presentation.clone());
                slot.activate.wallet.observe.phase = 59;
                Ok(!self.restricted)
            }
            Packet::WalletObserved { data, .. } => {
                data.validate()?;
                let w = &mut slot.activate.wallet.observe;
                let p = w
                    .wire
                    .as_ref()
                    .ok_or_else(|| rejected("wallet relay result before offer"))?;
                if w.reported || w.phase != 60 || !observed_matches(data, p) {
                    return Err(rejected("wallet relay actual result mismatch/replay"));
                }
                w.result = Some(data.clone());
                w.reported = true;
                w.phase = 61;
                Ok(true)
            }
            Packet::WalletFailed { data, .. } => {
                data.validate()?;
                slot.activate.wallet.validate_failure(data)?;
                slot.activate.wallet.terminal = true;
                self.restrict()?;
                Ok(true)
            }
            _ => Err(rejected("wrong wallet relay event")),
        }
    }
}
impl WalletSlots {
    fn validate_failure(&self, data: &SignerWalletFailureV1) -> Result<()> {
        if self.terminal {
            return Err(rejected("wallet failure repeated"));
        }
        let valid = match data.stage {
            SignerWalletFailureStageV1::PrepareFailed => {
                self.prepare
                    .wire
                    .as_ref()
                    .is_some_and(|p| p.presentation_digest == data.presentation_digest)
                    && matches!(self.prepare.phase, 56 | 57)
                    && !self.prepare.reported
            }
            SignerWalletFailureStageV1::ObserveUncertain => {
                self.observe
                    .wire
                    .as_ref()
                    .is_some_and(|p| p.presentation_digest == data.presentation_digest)
                    && matches!(self.observe.phase, 59 | 60)
                    && !self.observe.reported
            }
        };
        if !valid {
            return Err(rejected("wallet failure wrong original purpose"));
        }
        Ok(())
    }
    pub(super) fn observe_active(&self, phase: u8) -> Result<()> {
        self.sign.observe_active(phase)?;
        match phase {
            56 | 57 => self
                .prepare
                .binding
                .as_ref()
                .ok_or_else(|| rejected("active wallet Prepare missing"))?
                .bounds(),
            59 | 60 => self
                .observe
                .binding
                .as_ref()
                .ok_or_else(|| rejected("active wallet Observe missing"))?
                .bounds(),
            _ => Ok(()),
        }
    }
}
impl SignerFinancialWorkflowOriginV1 {
    pub fn report_wallet_failure(&mut self, data: SignerWalletFailureV1) -> Result<()> {
        data.validate()?;
        self.activate.wallet.validate_failure(&data)?;
        self.activate.wallet.terminal = true;
        self.restrict()?;
        self.send(&Packet::WalletFailed {
            role: self.target,
            data,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observe_requires_exact_actual_prepared_wallet_and_same_originals() {
        let p = crate::signer_wallet_data::tests::observe();
        let d = crate::signer_wallet_data::tests::prepared();
        let o = &p.facts.original;
        assert!(observe_matches(
            &p,
            &o.activation,
            &o.activated,
            p.service_ceiling_ms,
            p.writer_session_ceiling_ms,
            Some(&d)
        ));
        assert!(!observe_matches(
            &p,
            &o.activation,
            &o.activated,
            p.service_ceiling_ms,
            p.writer_session_ceiling_ms,
            None
        ));
        let mut bad = d;
        bad.wallet_review_digest = "ff".repeat(32);
        assert!(!observe_matches(
            &p,
            &o.activation,
            &o.activated,
            p.service_ceiling_ms,
            p.writer_session_ceiling_ms,
            Some(&bad)
        ));
    }
    #[test]
    fn actual_prepare_observation_cannot_replace_fixed_material() {
        let p = crate::signer_wallet_data::tests::prepare();
        let mut d = crate::signer_wallet_data::tests::prepared();
        assert!(prepared_matches(&d, &p));
        d.fixed_identity_digest = "ff".repeat(32);
        assert!(!prepared_matches(&d, &p));
    }
    #[test]
    fn every_wallet_step_remains_denied_under_r() {
        for (a, b) in [(55, 56), (56, 57), (57, 58), (58, 59), (59, 60), (60, 61)] {
            let p = state::Phases::new();
            p.step(0, 0, a).unwrap();
            p.revoke();
            assert!(p.step(0, a, b).is_err());
            assert_eq!(p.phase(0), a);
        }
    }
}

impl WalletSlots {
    pub(super) fn sign_predecessor(
        &self,
    ) -> Result<(&SignerWalletObservePresentationV1, &SignerWalletObservedV1)> {
        if self.terminal || !self.observe.reported || self.observe.phase != 61 {
            return Err(rejected("sign before actual wallet observation"));
        }
        Ok((
            self.observe
                .wire
                .as_ref()
                .ok_or_else(|| rejected("sign missing wallet presentation"))?,
            self.observe
                .result
                .as_ref()
                .ok_or_else(|| rejected("sign missing actual wallet result"))?,
        ))
    }
}
