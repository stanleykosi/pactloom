//! Nominal Prepare/Observe custody. Native and coordinated APIs share only
//! private checked wallet mechanics; a report never reconstructs a ticket.
use super::*;
#[path = "coordinated_financial_sign_v1.rs"]
mod coordinated_financial_sign_v1;
pub(in crate::native_ui) use coordinated_financial_sign_v1::PreparedCoordinatedSigningWalletV1;
use crate::account::birth::enrollment::roster_v2::financial_source_v1::CoordinatedWalletSourcePinV1;
use crate::native_peer::PeerProcess;
use wholepact_financial_coordinator_origin::{
    SignerWalletObserveFinalV1, SignerWalletObservedV1, SignerWalletOriginalV1,
    SignerWalletPrepareFinalV1, SignerWalletPreparePresentationV1, SignerWalletPreparedV1,
};

pub(in crate::native_ui) struct PreparedCoordinatedFinancialWalletV1 {
    inner: PreparedFinancialWalletV1,
    host: PeerProcess,
    presentation: SignerWalletPreparePresentationV1,
    original_source: Instant,
    original_service: Instant,
    original_writer: Instant,
}
/// Actual controller/ticket/inputs stay in the original Signer. No public
/// constructor, Clone, serde or conversion into native Sign permission exists.
pub(in crate::native_ui) struct ObservedCoordinatedFinancialWalletV1 {
    wallet: FinancialWalletCustodyV1,
    inputs: ReviewInputs,
    report: SignerWalletObservedV1,
    original: SignerWalletOriginalV1,
    original_source: Instant,
    original_service: Instant,
    original_writer: Instant,
}
impl ObservedCoordinatedFinancialWalletV1 {
    pub(in crate::native_ui) fn original(&self) -> &SignerWalletOriginalV1 {
        &self.original
    }
    pub(in crate::native_ui) fn report(&self) -> &SignerWalletObservedV1 {
        &self.report
    }
}
impl PreparedCoordinatedFinancialWalletV1 {
    pub(in crate::native_ui) fn configuration_digest(json: &str) -> Result<String> {
        coordinated_wallet_bounds_v1::configuration_digest(json)
    }
    pub(in crate::native_ui) fn prepare(
        source: Arc<PreparedOriginalFinancialSourceV1>,
        fixed: Arc<VerifiedDurableEconomicsV1>,
        host: PeerProcess,
        json: &str,
        action: SignerWalletPrepareFinalV1,
    ) -> Result<Self> {
        action.check_current()?;
        let presentation = action.presentation().clone();
        let original = &presentation.facts.original;
        let fixed_digest =
            crate::authority_bridge::durable_review_ipc_v3::verified_fixed_identity_digest_v3(
                fixed.verified().identity(),
            )
            .map_err(|_| Error::ReviewMismatch)?;
        if original.configuration_json != json
            || original.configuration_digest != Self::configuration_digest(json)?
            || original.fixed_identity_digest != fixed_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let original_source = action.original_source_deadline();
        let original_service = action.original_service_deadline();
        let original_writer = action.original_writer_session_deadline();
        let pin = source.prepare_coordinated_wallet_prepare_pin_v1(&host, &action)?;
        let account_id = source
            .account_for_coordinated_wallet_prepare_v1(&pin, &host, &action)?
            .account_id()?;
        action.check_current()?;
        let config = Config::parse_exact(json)?;
        let inner = PreparedFinancialWalletV1::build_from_checked_inputs(
            source,
            fixed,
            config,
            &account_id,
        )?;
        inner
            .source
            .check_coordinated_wallet_prepare_pin_v1(&pin, &host, &action)?;
        action.finish_prepare()?;
        Ok(Self {
            inner,
            host,
            presentation,
            original_source,
            original_service,
            original_writer,
        })
    }
    pub(in crate::native_ui) fn report(&self) -> SignerWalletPreparedV1 {
        let original = &self.presentation.facts.original;
        SignerWalletPreparedV1 {
            prepare_presentation_digest: self.presentation.presentation_digest.clone(),
            activation_presentation_digest: original.activation.presentation_digest.clone(),
            fixed_identity_digest: original.fixed_identity_digest.clone(),
            configuration_digest: original.configuration_digest.clone(),
            wallet_review_digest: self.inner.digest.clone(),
        }
    }
    pub(in crate::native_ui) fn original(&self) -> &SignerWalletOriginalV1 {
        &self.presentation.facts.original
    }
    pub(in crate::native_ui) fn prepare_presentation_digest(&self) -> &str {
        &self.presentation.presentation_digest
    }
    pub(in crate::native_ui) fn wallet_review_digest(&self) -> &str {
        &self.inner.digest
    }
    pub(in crate::native_ui) fn display(&self) -> Result<String> {
        Ok(format!(
            "Revalidate only the exact prepared source and guarded semantic journal pin; reread the same account FVK before one separately gated import. No new source/configuration or unrelated audit.\n{}",
            self.inner.display()?
        ))
    }
    pub(in crate::native_ui) fn original_deadlines(&self) -> (Instant, Instant, Instant) {
        (
            self.original_source,
            self.original_service,
            self.original_writer,
        )
    }
    pub(in crate::native_ui) async fn observe(
        self,
        action: SignerWalletObserveFinalV1,
    ) -> Result<ObservedCoordinatedFinancialWalletV1> {
        action.check_current()?;
        let p = action.presentation().clone();
        if p.facts.original != *self.original()
            || p.facts.prepare_presentation_digest != self.prepare_presentation_digest()
            || p.facts.wallet_review_digest != self.inner.digest
            || action.original_source_deadline() != self.original_source
            || action.original_service_deadline() != self.original_service
            || action.original_writer_session_deadline() != self.original_writer
        {
            return Err(Error::ReviewMismatch);
        }
        let pin = self
            .inner
            .source
            .prepare_coordinated_wallet_observe_pin_v1(&self.host, &action)?;
        let policy = self.inner.config.policy.clone();
        let guard = CoordinatedObserveGuard {
            action,
            pin,
            host: self.host,
        };
        let (deadline, _) = guard.budget()?;
        let (wallet, inputs, guard) = tokio::time::timeout_at(
            deadline.into(),
            self.inner
                .observe_kernel(WalletObservationGuard::Coordinated(guard)),
        )
        .await
        .map_err(|_| Error::Locked)??;
        let WalletObservationGuard::Coordinated(guard) = guard else {
            return Err(Error::Authentication);
        };
        guard.check(&wallet.source)?;
        let ticket = wallet.ticket.as_ref().ok_or(Error::Unavailable)?;
        ticket
            .validate_policy(&policy)
            .map_err(|_| Error::Verification)?;
        let evidence = ticket.evidence();
        let c = evidence.context();
        let tuples: Vec<_> = evidence
            .inputs()
            .iter()
            .map(|i| {
                (
                    i.input_id().to_owned(),
                    hex::encode(i.nullifier()),
                    i.value_zatoshis(),
                )
            })
            .collect();
        let wallet_observation_digest = observed_key_digest(
            &p.facts.original.fixed_identity_digest,
            &p.facts.original.configuration_digest,
            &p.facts.wallet_review_digest,
            evidence.account_id(),
            &hex::encode(Sha256::digest(evidence.fvk().to_bytes())),
            &(c.tip_height,hex::encode(c.tip_hash_protocol),c.anchor_height,
                hex::encode(c.anchor_hash_protocol),hex::encode(c.anchor_root)),
            &tuples,
        )?;
        let report = SignerWalletObservedV1 {
            observe_presentation_digest: p.presentation_digest.clone(),
            prepare_presentation_digest: p.facts.prepare_presentation_digest.clone(),
            activation_presentation_digest: p.facts.original.activation.presentation_digest.clone(),
            fixed_identity_digest: p.facts.original.fixed_identity_digest.clone(),
            configuration_digest: p.facts.original.configuration_digest.clone(),
            wallet_review_digest: p.facts.wallet_review_digest.clone(),
            wallet_observation_digest,
            tip_height: c.tip_height,
            tip_hash: hex::encode(c.tip_hash_protocol),
            anchor_height: c.anchor_height,
            anchor_hash: hex::encode(c.anchor_hash_protocol),
            anchor_root: hex::encode(c.anchor_root),
            input_count: u32::try_from(evidence.inputs().len()).map_err(|_| Error::InvalidData)?,
        };
        report.validate()?;
        guard.check(&wallet.source)?;
        guard.action.finish_observe()?;
        Ok(ObservedCoordinatedFinancialWalletV1 {
            wallet,
            inputs,
            report,
            original: p.facts.original.clone(),
            original_source: self.original_source,
            original_service: self.original_service,
            original_writer: self.original_writer,
        })
    }
}
pub(super) struct CoordinatedObserveGuard {
    action: SignerWalletObserveFinalV1,
    pin: CoordinatedWalletSourcePinV1,
    host: PeerProcess,
}
impl CoordinatedObserveGuard {
    pub(super) fn check(&self, source: &PreparedOriginalFinancialSourceV1) -> Result<()> {
        self.action.check_current()?;
        source.check_coordinated_wallet_observe_pin_v1(&self.pin, &self.host, &self.action)?;
        self.action.check_current()?;
        Ok(())
    }
    pub(super) fn account<'a>(
        &self,
        source: &'a PreparedOriginalFinancialSourceV1,
    ) -> Result<&'a crate::account::DedicatedAccount> {
        source.account_for_coordinated_wallet_observe_v1(&self.pin, &self.host, &self.action)
    }
    pub(super) fn import(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        wallet: &mut DedicatedTestnetWallet,
        fvk: &FullViewingKey,
        birthday: AccountBirthday,
    ) -> Result<()> {
        self.check(source)?;
        // The one-use entered gate covers only this actual synchronous import.
        // No await/network/wait or unrelated callback can occupy the exception.
        self.action.execute_wallet_observe_import(|| {
            diag::at(Stage::WalletImport);
            wallet
                .import_dedicated_fvk(fvk, birthday)
                .map(|_| ())
                .map_err(|error| {
                    diag::wallet(&error);
                    std::io::Error::other("dedicated viewing wallet import failed")
                })
        })?;
        self.check(source)
    }
    fn budget(&self) -> Result<(Instant, Duration)> {
        self.action.check_current()?;
        coordinated_wallet_bounds_v1::remaining_sync_budget(
            Instant::now(),
            self.action.original_observe_deadline(),
            self.action.original_source_deadline(),
            self.action.original_service_deadline(),
            self.action.original_writer_session_deadline(),
        )
    }
    pub(super) fn sync_budget(&self) -> Result<Duration> {
        Ok(self.budget()?.1)
    }
}

// Pure existing WalletObserve commitment, never a ticket/approval constructor.
fn observed_key_digest(fixed:&str,configuration:&str,review:&str,account:&str,fvk_digest:&str,
    context:&(u32,String,u32,String,String),inputs:&[(String,String,u64)])->Result<String>{
    wholepact_core::proposal::canonical_digest("wholepact:coordinated-financial-wallet-observation:v1",
        &(fixed,configuration,review,account,fvk_digest,context,inputs)).map_err(|_|Error::InvalidData)
}

