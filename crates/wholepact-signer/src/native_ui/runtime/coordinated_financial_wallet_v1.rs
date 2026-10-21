//! Consuming actual post-Activate owner. Prepare and Observe are separate real
//! actions. Completed observation stops before SignRead or key use.
use super::*;
#[path = "coordinated_financial_sign_v1.rs"]
pub(in crate::native_ui::runtime) mod coordinated_financial_sign_v1;
use crate::native_ui::wallet_workspace::financial_v1::{
    ObservedCoordinatedFinancialWalletV1, PreparedCoordinatedFinancialWalletV1,
};
use wholepact_financial_coordinator_origin::{
    SignerWalletObserveFactsV1, SignerWalletObserveFinalV1, SignerWalletObservePresentationV1,
    SignerWalletOriginalV1, SignerWalletPrepareFactsV1, SignerWalletPrepareFinalV1,
    SignerWalletPreparePresentationV1,
};

fn check_wallet_context(retained: &AwaitingCoordinatedWalletPrepareV1) -> Result<()> {
    let c = &retained.context;
    c.source.check_coordinated_public_custody_v2(
        c.original_peer.as_ref().ok_or(Error::Authentication)?,
    )?;
    if c.next != Next::Activate
        || c.writer.is_none()
        || c.material.is_none()
        || c.prepared_wallet.is_some()
        || c.wallet.is_some()
        || c.inputs.is_some()
        || c.prepared_spend.is_some()
        || c.active.is_some()
        || c.original_history.is_some()
        || c.history.is_some()
        || c.activation.is_some()
        || c.result_request.is_some()
        || retained.activated.active_writer_session.as_ref() != Some(&retained.receipt)
        || retained.activated.pending_writer_session.is_some()
        || retained.activated.head.digest != retained.activation_report.head_digest
        || retained.activated.head.sequence != retained.activation_report.head_sequence
        || retained.receipt.session_id != retained.activation_report.session_id
        || Instant::now() >= retained.original_writer_session_deadline
        || Instant::now() >= retained.original_service_deadline
    {
        return Err(Error::ReviewMismatch);
    }
    c.terms
        .require_live(wall_now()?)
        .map_err(|_| Error::Locked)?;
    Ok(())
}
fn wallet_ceiling(retained: &AwaitingCoordinatedWalletPrepareV1) -> Result<(Instant, u64, u64)> {
    check_wallet_context(retained)?;
    let now = Instant::now();
    let wall = wall_now()?;
    let deadline = action_deadline(
        now,
        retained.context.source.original_deadline(),
        retained.original_writer_session_deadline,
        retained.original_service_deadline,
    )?;
    let ms = u64::try_from(
        deadline
            .checked_duration_since(now)
            .ok_or(Error::Locked)?
            .as_millis(),
    )
    .map_err(|_| Error::Locked)?;
    let expires = wall
        .checked_add(ms)
        .ok_or(Error::Locked)?
        .min(retained.receipt.expires_at_ms)
        .min(retained.context.source.original_ceiling_ms());
    if expires <= wall {
        return Err(Error::Locked);
    }
    Ok((deadline, wall, expires))
}
pub(in crate::native_ui::runtime) struct PresentedCoordinatedWalletPrepareV1 {
    retained: AwaitingCoordinatedWalletPrepareV1,
    presentation: SignerWalletPreparePresentationV1,
    deadline: Instant,
}
pub(in crate::native_ui::runtime) struct PreparedCoordinatedWalletOwnerV1 {
    retained: AwaitingCoordinatedWalletPrepareV1,
    prepared: PreparedCoordinatedFinancialWalletV1,
}
pub(in crate::native_ui::runtime) struct PresentedCoordinatedWalletObserveV1 {
    retained: PreparedCoordinatedWalletOwnerV1,
    presentation: SignerWalletObservePresentationV1,
    deadline: Instant,
}
/// Failure retains original source/context and any completed wallet custody.
/// No method retries a consumed Prepare, import or observation.
pub(in crate::native_ui::runtime) struct FailedCoordinatedWalletV1 {
    retained: AwaitingCoordinatedWalletPrepareV1,
    prepared: Option<PreparedCoordinatedFinancialWalletV1>,
    observed: Option<ObservedCoordinatedFinancialWalletV1>,
    error: Error,
    failure: wholepact_financial_coordinator_origin::SignerWalletFailureV1,
}
pub(in crate::native_ui::runtime) struct AwaitingCoordinatedSignReadV1 {
    retained: AwaitingCoordinatedWalletPrepareV1,
    wallet: ObservedCoordinatedFinancialWalletV1,
}
impl AwaitingCoordinatedWalletPrepareV1 {
    pub(in crate::native_ui::runtime) fn offer_wallet_prepare(
        self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<PresentedCoordinatedWalletPrepareV1> {
        let (deadline, reviewed_at_ms, expires_at_ms) = wallet_ceiling(&self)?;
        let c = &self.context;
        let json = c.wallet_setup.to_string();
        let fixed_identity_digest =
            crate::authority_bridge::durable_review_ipc_v3::verified_fixed_identity_digest_v3(
                c.material
                    .as_ref()
                    .ok_or(Error::Unavailable)?
                    .verified()
                    .identity(),
            )
            .map_err(|_| Error::ReviewMismatch)?;
        let original = SignerWalletOriginalV1 {
            activation: self.activation_presentation.clone(),
            activated: self.activation_report.clone(),
            fixed_identity_digest,
            configuration_digest: PreparedCoordinatedFinancialWalletV1::configuration_digest(
                &json,
            )?,
            configuration_json: json,
        };
        let facts=SignerWalletPrepareFactsV1 {original,reviewed_at_ms,expires_at_ms,display:"Prepare the exact original fixed viewing-wallet configuration and original account. No FVK import, provider network request, ticket, key use or signature is permitted by Prepare.".into()};
        let presentation = origin.offer_wallet_prepare(facts, deadline)?;
        check_wallet_context(&self)?;
        Ok(PresentedCoordinatedWalletPrepareV1 {
            retained: self,
            presentation,
            deadline,
        })
    }
}
impl PresentedCoordinatedWalletPrepareV1 {
    pub(in crate::native_ui::runtime) fn consume_final(
        mut self,
        action: SignerWalletPrepareFinalV1,
    ) -> std::result::Result<UnreportedCoordinatedWalletPreparedV1, FailedCoordinatedWalletV1> {
        let result = (|| -> Result<PreparedCoordinatedFinancialWalletV1> {
            action.check_current()?;
            check_wallet_context(&self.retained)?;
            let c = &self.retained.context;
            if action.presentation() != &self.presentation
                || action.original_prepare_deadline() != self.deadline
                || action.original_source_deadline() != c.source.original_deadline()
                || action.original_service_deadline() != self.retained.original_service_deadline
                || action.original_writer_session_deadline()
                    != self.retained.original_writer_session_deadline
            {
                return Err(Error::ReviewMismatch);
            }
            PreparedCoordinatedFinancialWalletV1::prepare(
                Arc::clone(&c.source),
                Arc::clone(c.material.as_ref().ok_or(Error::Unavailable)?),
                c.original_peer
                    .as_ref()
                    .ok_or(Error::Authentication)?
                    .clone(),
                &c.wallet_setup,
                action,
            )
        })();
        let prepared = match result {
            Ok(p) => p,
            Err(error) => {
                return Err(FailedCoordinatedWalletV1 {
                    retained: self.retained,
                    prepared: None,
                    observed: None,
                    error,
                    failure: wallet_failure(&self.presentation.presentation_digest, wholepact_financial_coordinator_origin::SignerWalletFailureStageV1::PrepareFailed),
                });
            }
        };
        self.retained.context.wallet_setup.zeroize();
        Ok(UnreportedCoordinatedWalletPreparedV1 {
            owner: PreparedCoordinatedWalletOwnerV1 {
                retained: self.retained,
                prepared,
            },
        })
    }
}
impl PreparedCoordinatedWalletOwnerV1 {
    pub(in crate::native_ui::runtime) fn offer_wallet_observe(
        self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<PresentedCoordinatedWalletObserveV1> {
        let (deadline, reviewed_at_ms, expires_at_ms) = wallet_ceiling(&self.retained)?;
        let facts = SignerWalletObserveFactsV1 {
            original: self.prepared.original().clone(),
            prepare_presentation_digest: self.prepared.prepare_presentation_digest().into(),
            wallet_review_digest: self.prepared.wallet_review_digest().into(),
            reviewed_at_ms,
            expires_at_ms,
            display: self.prepared.display()?,
        };
        let presentation = origin.offer_wallet_observe(facts, deadline)?;
        check_wallet_context(&self.retained)?;
        Ok(PresentedCoordinatedWalletObserveV1 {
            retained: self,
            presentation,
            deadline,
        })
    }
}
impl PresentedCoordinatedWalletObserveV1 {
    pub(in crate::native_ui::runtime) fn consume_final(
        self,
        action: SignerWalletObserveFinalV1,
    ) -> std::result::Result<UnreportedCoordinatedWalletObservedV1, FailedCoordinatedWalletV1> {
        let PreparedCoordinatedWalletOwnerV1 { retained, prepared } = self.retained;
        let check = (|| -> Result<()> {
            action.check_current()?;
            check_wallet_context(&retained)?;
            if action.presentation() != &self.presentation
                || action.original_observe_deadline() != self.deadline
                || action.original_source_deadline() != retained.context.source.original_deadline()
                || action.original_service_deadline() != retained.original_service_deadline
                || action.original_writer_session_deadline()
                    != retained.original_writer_session_deadline
            {
                return Err(Error::ReviewMismatch);
            }
            Ok(())
        })();
        if let Err(error) = check {
            return Err(FailedCoordinatedWalletV1 {
                retained,
                prepared: Some(prepared),
                observed: None,
                error,
                failure: wallet_failure(&self.presentation.presentation_digest, wholepact_financial_coordinator_origin::SignerWalletFailureStageV1::ObserveUncertain),
            });
        }
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => {
                return Err(FailedCoordinatedWalletV1 {
                    retained,
                    prepared: Some(prepared),
                    observed: None,
                    error: Error::Unavailable,
                    failure: wallet_failure(&self.presentation.presentation_digest, wholepact_financial_coordinator_origin::SignerWalletFailureStageV1::ObserveUncertain),
                });
            }
        };
        let observed = match runtime.block_on(prepared.observe(action)) {
            Ok(observed) => observed,
            Err(error) => {
                return Err(FailedCoordinatedWalletV1 {
                    retained,
                    prepared: None,
                    observed: None,
                    error,
                failure: wallet_failure(&self.presentation.presentation_digest, wholepact_financial_coordinator_origin::SignerWalletFailureStageV1::ObserveUncertain),
                });
            }
        };
        Ok(UnreportedCoordinatedWalletObservedV1 {
            owner: AwaitingCoordinatedSignReadV1 {
                retained,
                wallet: observed,
            },
        })
    }
}

fn wallet_failure(
    presentation_digest: &str,
    stage: wholepact_financial_coordinator_origin::SignerWalletFailureStageV1,
) -> wholepact_financial_coordinator_origin::SignerWalletFailureV1 {
    wholepact_financial_coordinator_origin::SignerWalletFailureV1 {
        presentation_digest: presentation_digest.into(),
        stage,
    }
}
impl FailedCoordinatedWalletV1 {
    pub(in crate::native_ui::runtime) fn report_failure(
        &self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> Result<()> {
        origin
            .report_wallet_failure(self.failure.clone())
            .map_err(Into::into)
    }
}
// These are genuine worker outputs, not ordinary report-data constructors.
// Main-thread reporting consumes the output before any next action is offered.
pub(in crate::native_ui::runtime) struct UnreportedCoordinatedWalletPreparedV1 {
    owner: PreparedCoordinatedWalletOwnerV1,
}
impl UnreportedCoordinatedWalletPreparedV1 {
    pub(in crate::native_ui::runtime) fn report(
        self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> std::result::Result<PreparedCoordinatedWalletOwnerV1, FailedCoordinatedWalletV1> {
        if let Err(error) = origin.report_wallet_prepared(self.owner.prepared.report()) {
            let failure = wallet_failure(
                self.owner.prepared.prepare_presentation_digest(),
                wholepact_financial_coordinator_origin::SignerWalletFailureStageV1::PrepareFailed,
            );
            return Err(FailedCoordinatedWalletV1 {
                retained: self.owner.retained,
                prepared: Some(self.owner.prepared),
                observed: None,
                error: error.into(),
                failure,
            });
        }
        Ok(self.owner)
    }
}
pub(in crate::native_ui::runtime) struct UnreportedCoordinatedWalletObservedV1 {
    owner: AwaitingCoordinatedSignReadV1,
}
impl UnreportedCoordinatedWalletObservedV1 {
    pub(in crate::native_ui::runtime) fn report(
        self,
        origin: &mut SignerFinancialWorkflowOriginV1,
    ) -> std::result::Result<AwaitingCoordinatedSignReadV1, FailedCoordinatedWalletV1> {
        if let Err(error) = origin.report_wallet_observed(self.owner.wallet.report().clone()) {
            let failure = wallet_failure(&self.owner.wallet.report().observe_presentation_digest, wholepact_financial_coordinator_origin::SignerWalletFailureStageV1::ObserveUncertain);
            return Err(FailedCoordinatedWalletV1 {
                retained: self.owner.retained,
                prepared: None,
                observed: Some(self.owner.wallet),
                error: error.into(),
                failure,
            });
        }
        Ok(self.owner)
    }
}
