//! Wallet-specific source reads under genuine nominal Finals. Pins are inert
//! revision observations, never transferable Prepare/Observe permissions.
use super::*;
use crate::consent_journal::FinancialOperationJournalPinV1;
use crate::native_peer::PeerProcess;
use wholepact_financial_coordinator_origin::{
    SignerWalletObserveFinalV1, SignerWalletOriginalV1, SignerWalletPrepareFinalV1,
};

#[derive(PartialEq, Eq)]
enum Purpose {
    Prepare,
    Observe,
}
pub(crate) struct CoordinatedWalletSourcePinV1 {
    source_identity: String,
    presentation_digest: String,
    purpose: Purpose,
    journal: FinancialOperationJournalPinV1,
}
enum Action<'a> {
    Prepare(&'a SignerWalletPrepareFinalV1),
    Observe(&'a SignerWalletObserveFinalV1),
}
impl Action<'_> {
    fn check(&self) -> Result<()> {
        match self {
            Self::Prepare(a) => a.check_current(),
            Self::Observe(a) => a.check_current(),
        }
        .map_err(Into::into)
    }
    fn original(&self) -> &SignerWalletOriginalV1 {
        match self {
            Self::Prepare(a) => &a.presentation().facts.original,
            Self::Observe(a) => &a.presentation().facts.original,
        }
    }
    fn presentation_digest(&self) -> &str {
        match self {
            Self::Prepare(a) => &a.presentation().presentation_digest,
            Self::Observe(a) => &a.presentation().presentation_digest,
        }
    }
    fn purpose(&self) -> Purpose {
        match self {
            Self::Prepare(_) => Purpose::Prepare,
            Self::Observe(_) => Purpose::Observe,
        }
    }
    fn source_deadline(&self) -> Instant {
        match self {
            Self::Prepare(a) => a.original_source_deadline(),
            Self::Observe(a) => a.original_source_deadline(),
        }
    }
}
impl PreparedOriginalFinancialSourceV1 {
    fn check_wallet_action(&self, host: &PeerProcess, action: &Action<'_>) -> Result<()> {
        action.check()?;
        let original = action.original();
        let activation = &original.activation;
        activation.validate()?;
        original.activated.validate()?;
        let facts = &activation.facts.original;
        if action.source_deadline() != self.original_deadline
            || facts.source_identity_digest != self.identity
            || facts.source_expires_at_ms != self.original_ceiling_ms
            || facts.original_host_process_instance != host.instance()
            || original.activated.presentation_digest != activation.presentation_digest
            || original.activated.session_id != facts.acquired.session_id
        {
            return Err(Error::ReviewMismatch);
        }
        // Metadata/currentness only until the exact Final samples inside SQL.
        self.check_coordinated_public_custody_v2(host)?;
        action.check()?;
        Ok(())
    }
    fn prepare_wallet_pin(
        &self,
        host: &PeerProcess,
        action: Action<'_>,
    ) -> Result<CoordinatedWalletSourcePinV1> {
        self.check_wallet_action(host, &action)?;
        let journal = {
            let binding = self.financial_binding()?;
            action.check()?;
            match &action {
                Action::Prepare(a) => self
                    .financial_journal()?
                    .prepare_coordinated_wallet_prepare_operation_pin_v1(&binding, a)?,
                Action::Observe(a) => self
                    .financial_journal()?
                    .prepare_coordinated_wallet_observe_operation_pin_v1(&binding, a)?,
            }
        };
        action.check()?;
        let original = &action.original().activation.facts.original;
        if serde_json::to_string(journal.continuation_request()).map_err(|_| Error::InvalidData)?
            != original.continuation_request_json
            || journal
                .terms()
                .intent_terms_digest()
                .map_err(|_| Error::InvalidData)?
                != original.terms_digest
            || journal.terms().valid_until_ms != self.original_ceiling_ms
        {
            return Err(Error::ReviewMismatch);
        }
        let pin = CoordinatedWalletSourcePinV1 {
            source_identity: self.identity.clone(),
            presentation_digest: action.presentation_digest().into(),
            purpose: action.purpose(),
            journal,
        };
        self.check_wallet_pin(&pin, host, &action)?;
        Ok(pin)
    }
    fn check_wallet_pin(
        &self,
        pin: &CoordinatedWalletSourcePinV1,
        host: &PeerProcess,
        action: &Action<'_>,
    ) -> Result<()> {
        self.check_wallet_action(host, action)?;
        if pin.source_identity != self.identity
            || pin.presentation_digest != action.presentation_digest()
            || pin.purpose != action.purpose()
        {
            return Err(Error::ReviewMismatch);
        }
        {
            let binding = self.financial_binding()?;
            action.check()?;
            match action {
                Action::Prepare(a) => self
                    .financial_journal()?
                    .check_coordinated_wallet_prepare_operation_pin_v1(&binding, &pin.journal, a)?,
                Action::Observe(a) => self
                    .financial_journal()?
                    .check_coordinated_wallet_observe_operation_pin_v1(&binding, &pin.journal, a)?,
            }
        }
        self.check_wallet_action(host, action)
    }
    pub(crate) fn prepare_coordinated_wallet_prepare_pin_v1(
        &self,
        host: &PeerProcess,
        action: &SignerWalletPrepareFinalV1,
    ) -> Result<CoordinatedWalletSourcePinV1> {
        self.prepare_wallet_pin(host, Action::Prepare(action))
    }
    pub(crate) fn prepare_coordinated_wallet_observe_pin_v1(
        &self,
        host: &PeerProcess,
        action: &SignerWalletObserveFinalV1,
    ) -> Result<CoordinatedWalletSourcePinV1> {
        self.prepare_wallet_pin(host, Action::Observe(action))
    }
    pub(crate) fn check_coordinated_wallet_prepare_pin_v1(
        &self,
        pin: &CoordinatedWalletSourcePinV1,
        host: &PeerProcess,
        action: &SignerWalletPrepareFinalV1,
    ) -> Result<()> {
        self.check_wallet_pin(pin, host, &Action::Prepare(action))
    }
    pub(crate) fn check_coordinated_wallet_observe_pin_v1(
        &self,
        pin: &CoordinatedWalletSourcePinV1,
        host: &PeerProcess,
        action: &SignerWalletObserveFinalV1,
    ) -> Result<()> {
        self.check_wallet_pin(pin, host, &Action::Observe(action))
    }
    pub(crate) fn account_for_coordinated_wallet_prepare_v1(
        &self,
        pin: &CoordinatedWalletSourcePinV1,
        host: &PeerProcess,
        action: &SignerWalletPrepareFinalV1,
    ) -> Result<&crate::account::DedicatedAccount> {
        self.check_coordinated_wallet_prepare_pin_v1(pin, host, action)?;
        Ok(self.retained.account.account())
    }
    pub(crate) fn account_for_coordinated_wallet_observe_v1(
        &self,
        pin: &CoordinatedWalletSourcePinV1,
        host: &PeerProcess,
        action: &SignerWalletObserveFinalV1,
    ) -> Result<&crate::account::DedicatedAccount> {
        self.check_coordinated_wallet_observe_pin_v1(pin, host, action)?;
        Ok(self.retained.account.account())
    }
}
