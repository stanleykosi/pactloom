//! C-only CompletedPair review state. This leaf neither reads protected storage
//! nor sends a packet. The parent must run `action` only in its existing final
//! visible native tail, after focus, later-frame, read-to-end and acknowledgment
//! checks. Ordinary expected inputs are correlation, never retirement evidence.
use crate::{rejected, Result};
use std::time::Instant;
use wholepact_financial_coordinator_origin::{
    CompletedPairInputsV1, CoordinatorCompletedPairEventV1, CoordinatorFinancialNativeV1,
    FinancialCompletedPairReviewTicketV1, FinancialCompletedPairServeOutboundV1,
    FinancialCompletedPairServingV1, FinancialCompletedPairSetupOutboundV1,
    FinancialCompletedPairSetupTicketV1,
};

const MAX_DISPLAY_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(super) enum PairStage {
    #[default]
    Idle,
    Preparing,
    SetupReview,
    PreparingService,
    ServeReview,
    StartingService,
    Serving,
    Failed,
    Disposed,
    Closed,
}

pub(super) struct PairPreparation {
    pub(super) inputs: CompletedPairInputsV1,
    pub(super) deadline: Instant,
}

pub(super) enum PairOutbound {
    Setup(FinancialCompletedPairSetupOutboundV1),
    Serve(FinancialCompletedPairServeOutboundV1),
}

#[derive(Default)]
pub(super) struct PairFlow {
    stage: PairStage,
    expected_inputs: Option<CompletedPairInputsV1>,
    original_ceiling: Option<Instant>,
    setup: Option<FinancialCompletedPairSetupTicketV1>,
    review: Option<FinancialCompletedPairReviewTicketV1>,
    serving: Option<FinancialCompletedPairServingV1>,
    disposed: bool,
}

impl PairFlow {
    pub(super) fn stage(&self) -> PairStage { self.stage }
    pub(super) fn is_started(&self) -> bool { self.stage != PairStage::Idle }

    /// Select once. The driver asks the original endpoint for the actual opaque
    /// ticket; parsing/validating these inputs does not create that ticket.
    pub(super) fn begin(&mut self, inputs: CompletedPairInputsV1, original_ceiling: Instant) -> Result<PairPreparation> {
        if self.stage != PairStage::Idle || Instant::now() >= original_ceiling {
            return Err(rejected("completed pair selection consumed or expired"));
        }
        inputs.validate()?;
        self.expected_inputs = Some(inputs.clone());
        self.original_ceiling = Some(original_ceiling);
        self.stage = PairStage::Preparing;
        Ok(PairPreparation { inputs, deadline: original_ceiling })
    }

    pub(super) fn accept_setup(&mut self, ticket: FinancialCompletedPairSetupTicketV1) -> Result<()> {
        if self.stage != PairStage::Preparing || self.setup.is_some()
            || self.expected_inputs.as_ref() != Some(ticket.inputs())
            || self.original_ceiling.is_none_or(|d| ticket.native_deadline() > d) {
            return Err(rejected("completed pair Setup correlation changed"));
        }
        ticket.inputs().require_original(ticket.original_binding())?;
        ticket.check_current()?;
        self.setup = Some(ticket);
        self.stage = PairStage::SetupReview;
        Ok(())
    }

    pub(super) fn accept_event(&mut self, event: CoordinatorCompletedPairEventV1) -> Result<()> {
        match event {
            CoordinatorCompletedPairEventV1::Display(ticket) => {
                if self.stage != PairStage::PreparingService || self.review.is_some() {
                    return Err(rejected("completed pair unexpected review"));
                }
                ticket.check_current()?;
                let expected = self.expected_inputs.as_ref().ok_or_else(|| rejected("completed pair selection missing"))?;
                expected.require_original(&ticket.presentation().original)?;
                ticket.presentation().validate()?;
                self.review = Some(ticket);
                self.stage = PairStage::ServeReview;
            }
            CoordinatorCompletedPairEventV1::Serving(serving) => {
                if self.stage != PairStage::StartingService || self.serving.is_some() {
                    return Err(rejected("completed pair unexpected service acknowledgment"));
                }
                serving.check_current()?;
                self.expected_inputs.as_ref().ok_or_else(|| rejected("completed pair selection missing"))?
                    .require_original(&serving.presentation().original)?;
                self.serving = Some(serving);
                self.stage = PairStage::Serving;
            }
            CoordinatorCompletedPairEventV1::PreparationFailed
            | CoordinatorCompletedPairEventV1::ServiceFailed
            | CoordinatorCompletedPairEventV1::Restricted => {
                self.clear_actions();
                return Err(rejected("completed pair failed or restricted"));
            }
            CoordinatorCompletedPairEventV1::Disposed => {
                if !disposal_allowed(self.stage) || self.disposed {
                    return Err(rejected("completed pair unexpected disposal"));
                }
                self.setup = None;
                self.review = None;
                self.serving = None;
                self.disposed = true;
                self.stage = PairStage::Disposed;
            }
            CoordinatorCompletedPairEventV1::PurposeClosed => {
                if self.stage != PairStage::Disposed || !self.disposed {
                    return Err(rejected("completed pair close before actual disposal"));
                }
                self.stage = PairStage::Closed;
            }
        }
        Ok(())
    }

    pub(super) fn serving(&self) -> Option<&FinancialCompletedPairServingV1> {
        if self.stage == PairStage::Serving { self.serving.as_ref() } else { None }
    }

    pub(super) fn current(&self) -> Result<()> {
        match self.stage {
            PairStage::Idle | PairStage::Disposed | PairStage::Closed => Ok(()),
            PairStage::Failed => Err(rejected("completed pair terminal failure")),
            PairStage::SetupReview => self.setup.as_ref().ok_or_else(|| rejected("completed pair Setup missing"))?.check_current(),
            PairStage::ServeReview => self.review.as_ref().ok_or_else(|| rejected("completed pair review missing"))?.check_current(),
            PairStage::Serving => self.serving.as_ref().ok_or_else(|| rejected("completed pair service missing"))?.check_current(),
            PairStage::Preparing | PairStage::PreparingService | PairStage::StartingService => {
                if self.original_ceiling.is_none_or(|d| Instant::now() >= d) {
                    Err(rejected("completed pair original local ceiling expired"))
                } else { Ok(()) }
            }
        }
    }

    /// No GUI input is read here. Only the parent final native tail may call
    /// this after the full current review was visibly read and acknowledged.
    pub(super) fn action(&mut self, native: &CoordinatorFinancialNativeV1) -> Result<PairOutbound> {
        self.current()?;
        match self.stage {
            PairStage::SetupReview => {
                let ticket = self.setup.take().ok_or_else(|| rejected("completed pair Setup consumed"))?;
                self.stage = PairStage::Failed;
                let outbound = native.admit_completed_pair_setup(ticket)?;
                self.stage = PairStage::PreparingService;
                Ok(PairOutbound::Setup(outbound))
            }
            PairStage::ServeReview => {
                let ticket = self.review.take().ok_or_else(|| rejected("completed pair Serve consumed"))?;
                self.stage = PairStage::Failed;
                let outbound = native.admit_completed_pair_serve(ticket)?;
                self.stage = PairStage::StartingService;
                Ok(PairOutbound::Serve(outbound))
            }
            _ => Err(rejected("completed pair has no current native action")),
        }
    }

    pub(super) fn display(&self) -> Result<(String, Option<&'static str>, bool)> {
        let (text, button, ack) = match self.stage {
            PairStage::SetupReview => {
                let ticket = self.setup.as_ref().ok_or_else(|| rejected("completed pair Setup missing"))?;
                let text = serde_json::to_string_pretty(&serde_json::json!({
                    "purpose": "CompletedPair Setup only: open the original shared namespace and prepare both original accounts; no Return or dispatch approval",
                    "inputs": ticket.inputs(), "original": ticket.original_binding()
                })).map_err(|_| rejected("completed pair Setup display encoding"))?;
                (text, Some("Approve CompletedPair Setup only"), true)
            }
            PairStage::ServeReview => {
                let ticket = self.review.as_ref().ok_or_else(|| rejected("completed pair review missing"))?;
                let text = serde_json::to_string_pretty(ticket.presentation()).map_err(|_| rejected("completed pair display encoding"))?;
                (text, Some("Approve original CompletedPair service only"), true)
            }
            PairStage::Serving => ("Both original accounts have an authenticated CompletedPair service acknowledgment. Each Return still requires its own native review. No transaction is dispatched by this step.".into(), None, false),
            PairStage::Failed => ("CompletedPair stopped. No automatic retry, replacement authority, or renewed deadline is permitted.".into(), None, false),
            PairStage::Disposed | PairStage::Closed => ("CompletedPair resource custody ended. This alone is not full-product completion or proof of all process reaps.".into(), None, false),
            _ => ("Waiting for the original CompletedPair resource step. No consent is supplied automatically.".into(), None, false),
        };
        if text.len() > MAX_DISPLAY_BYTES { return Err(rejected("completed pair display exceeds fixed bound")); }
        Ok((text, button, ack))
    }

    /// Restrictive teardown only, never normal-completion evidence. Dropping
    /// unconsumed tickets publishes their original restriction through Origin.
    pub(super) fn clear_actions(&mut self) {
        self.stage = PairStage::Failed;
        self.setup = None;
        self.review = None;
        self.serving = None;
    }
}

fn disposal_allowed(stage: PairStage) -> bool {
    matches!(stage, PairStage::Preparing | PairStage::PreparingService | PairStage::StartingService | PairStage::Serving | PairStage::Failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_pair_idle_is_not_service_or_native_review() {
        let flow = PairFlow::default();
        assert_eq!(flow.stage(), PairStage::Idle);
        assert!(!flow.is_started());
        assert!(flow.serving().is_none());
        let (_, button, ack) = flow.display().unwrap();
        assert!(button.is_none());
        assert!(!ack);
    }
    #[test]
    fn completed_pair_close_requires_actual_disposed_event() {
        let mut flow = PairFlow::default();
        assert!(flow.accept_event(CoordinatorCompletedPairEventV1::PurposeClosed).is_err());
        assert_eq!(flow.stage(), PairStage::Idle);
    }
    #[test]
    fn completed_pair_restrictive_clear_never_becomes_success() {
        let mut flow = PairFlow::default();
        flow.clear_actions();
        assert_eq!(flow.stage(), PairStage::Failed);
        assert!(flow.current().is_err());
        assert!(flow.serving().is_none());
        assert!(flow.accept_event(CoordinatorCompletedPairEventV1::Disposed).is_ok());
        assert!(flow.accept_event(CoordinatorCompletedPairEventV1::PurposeClosed).is_ok());
        assert_eq!(flow.stage(), PairStage::Closed);
        assert!(flow.serving().is_none());
    }
    #[test]
    fn completed_pair_disposal_does_not_skip_native_review() {
        for stage in [PairStage::Idle, PairStage::SetupReview, PairStage::ServeReview, PairStage::Disposed, PairStage::Closed] {
            assert!(!disposal_allowed(stage));
        }
    }
}
