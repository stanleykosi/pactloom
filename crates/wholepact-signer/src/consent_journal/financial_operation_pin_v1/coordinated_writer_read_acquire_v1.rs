//! Concrete coordinated writer-Read and Acquire operation pins. This private
//! child preserves the maintained audit and metadata-only callback split.
//! Every semantic reread requires the actual still-live nominal Read or Arm.
use super::*;
use wholepact_financial_coordinator_origin::{
    SignerAcquireArmV1, SignerAcquireFinalV1, SignerActivateArmV1, SignerActivateFinalV1,
    SignerActivateReadFinalV1, SignerFinancialWriterReadFinalV1, SignerWalletObserveFinalV1,
    SignerWalletPrepareFinalV1, SignerSignReadFinalV1,
};

// Closed observations, never a caller-supplied callback or a DTO permission.
enum OperationObservation<'a> {
    SignRead(&'a SignerSignReadFinalV1),
    WalletPrepare(&'a SignerWalletPrepareFinalV1),
    WalletObserve(&'a SignerWalletObserveFinalV1),
    ActivateRead(&'a SignerActivateReadFinalV1),
    ActivateArm(&'a SignerActivateArmV1),
    ActivateFinal(&'a SignerActivateFinalV1),
    Read(&'a SignerFinancialWriterReadFinalV1),
    Arm(&'a SignerAcquireArmV1),
    Final(&'a SignerAcquireFinalV1),
}
impl OperationObservation<'_> {
    fn check(&self) -> Result<()> {
        match self {
            Self::SignRead(token) => token.check_current(),
            Self::WalletPrepare(token) => token.check_current(),
            Self::WalletObserve(token) => token.check_current(),
            Self::ActivateRead(token) => token.check_current(),
            Self::ActivateArm(token) => token.check_current(),
            Self::ActivateFinal(token) => token.check_current(),
            Self::Read(token) => token.check_current(),
            Self::Arm(token) => token.check_current(),
            Self::Final(token) => token.check_current(),
        }
        .map_err(|_| JournalError::Permission)
    }
}

fn require_operation_read_pin(
    current: &FinancialSourceBindingV1,
    c: &Connection,
    guard: &OperationObservation<'_>,
) -> Result<()> {
    // The effect Final permits only the already captured metadata pin, not a
    // newly audited source or an implicit second local preparation.
    if matches!(
        guard,
        OperationObservation::Final(_) | OperationObservation::ActivateFinal(_)
    ) {
        return Err(JournalError::Permission);
    }
    guard.check()?;
    if current.revision != revision(c)? {
        return Err(JournalError::Conflict);
    }
    guard.check()?;
    if let Some(expected) = &current.continuation_digest {
        let retained = intent::read(c)?;
        guard.check()?;
        if retained.history_digest()? != *expected {
            return Err(JournalError::Conflict);
        }
    }
    guard.check()
}

impl FinancialOperationJournalPinV1 {
    pub(crate) fn coordinated_operation_pin_digest_v1(&self) -> Result<String> {
        let revision = &self.custody.revision;
        digest(
            "wholepact:coordinated-financial-operation-journal-pin:v1",
            &(
                hex::encode(self.custody.identity.origin_commitment()),
                &self.custody.current_identity,
                &self.original_rows_digest,
                &self.history_digest,
                self.retained.request(),
                (
                    revision.application_id,
                    revision.data_version,
                    revision.total_changes,
                    revision.schema_version,
                    revision.user_version,
                ),
            ),
        )
    }
}

impl FinancialConsentJournalV1 {
    pub(crate) fn prepare_coordinated_sign_read_operation_pin_v1(&self,current:&FinancialSourceBindingV1,token:&SignerSignReadFinalV1)->Result<FinancialOperationJournalPinV1>{self.prepare_coordinated_operation_pin_v1(current,OperationObservation::SignRead(token))}
    pub(crate) fn check_coordinated_sign_read_operation_pin_v1(&self,current:&FinancialSourceBindingV1,pin:&FinancialOperationJournalPinV1,token:&SignerSignReadFinalV1)->Result<()>{self.check_coordinated_operation_pin_v1(current,pin,OperationObservation::SignRead(token))}

    pub(crate) fn prepare_coordinated_wallet_prepare_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        token: &SignerWalletPrepareFinalV1,
    ) -> Result<FinancialOperationJournalPinV1> {
        self.prepare_coordinated_operation_pin_v1(
            current,
            OperationObservation::WalletPrepare(token),
        )
    }
    pub(crate) fn prepare_coordinated_wallet_observe_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        token: &SignerWalletObserveFinalV1,
    ) -> Result<FinancialOperationJournalPinV1> {
        self.prepare_coordinated_operation_pin_v1(
            current,
            OperationObservation::WalletObserve(token),
        )
    }
    pub(crate) fn check_coordinated_wallet_prepare_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        pin: &FinancialOperationJournalPinV1,
        token: &SignerWalletPrepareFinalV1,
    ) -> Result<()> {
        self.check_coordinated_operation_pin_v1(
            current,
            pin,
            OperationObservation::WalletPrepare(token),
        )
    }
    pub(crate) fn check_coordinated_wallet_observe_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        pin: &FinancialOperationJournalPinV1,
        token: &SignerWalletObserveFinalV1,
    ) -> Result<()> {
        self.check_coordinated_operation_pin_v1(
            current,
            pin,
            OperationObservation::WalletObserve(token),
        )
    }

    pub(crate) fn prepare_coordinated_activate_read_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        token: &SignerActivateReadFinalV1,
    ) -> Result<FinancialOperationJournalPinV1> {
        self.prepare_coordinated_operation_pin_v1(
            current,
            OperationObservation::ActivateRead(token),
        )
    }
    pub(crate) fn prepare_coordinated_activate_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        token: &SignerActivateArmV1,
    ) -> Result<FinancialOperationJournalPinV1> {
        self.prepare_coordinated_operation_pin_v1(current, OperationObservation::ActivateArm(token))
    }
    pub(crate) fn check_coordinated_activate_read_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        pin: &FinancialOperationJournalPinV1,
        token: &SignerActivateReadFinalV1,
    ) -> Result<()> {
        self.check_coordinated_operation_pin_v1(
            current,
            pin,
            OperationObservation::ActivateRead(token),
        )
    }
    pub(crate) fn check_coordinated_activate_arm_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        pin: &FinancialOperationJournalPinV1,
        token: &SignerActivateArmV1,
    ) -> Result<()> {
        self.check_coordinated_operation_pin_v1(
            current,
            pin,
            OperationObservation::ActivateArm(token),
        )
    }
    pub(crate) fn check_coordinated_activate_final_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        pin: &FinancialOperationJournalPinV1,
        token: &SignerActivateFinalV1,
    ) -> Result<()> {
        self.check_coordinated_operation_pin_v1(
            current,
            pin,
            OperationObservation::ActivateFinal(token),
        )
    }

    pub(crate) fn prepare_coordinated_writer_read_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        read: &SignerFinancialWriterReadFinalV1,
    ) -> Result<FinancialOperationJournalPinV1> {
        self.prepare_coordinated_operation_pin_v1(current, OperationObservation::Read(read))
    }

    pub(crate) fn prepare_coordinated_acquire_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        arm: &SignerAcquireArmV1,
    ) -> Result<FinancialOperationJournalPinV1> {
        self.prepare_coordinated_operation_pin_v1(current, OperationObservation::Arm(arm))
    }

    fn prepare_coordinated_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        guard: OperationObservation<'_>,
    ) -> Result<FinancialOperationJournalPinV1> {
        if matches!(
            guard,
            OperationObservation::Final(_) | OperationObservation::ActivateFinal(_)
        ) {
            return Err(JournalError::Permission);
        }
        guard.check()?;
        let _fence = self
            .journal
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        guard.check()?;
        let mut c = self
            .journal
            .connection
            .lock()
            .map_err(|_| JournalError::Database)?;
        guard.check()?;
        if !c.is_autocommit() {
            return Err(JournalError::Conflict);
        }
        current.require(&self.journal, &c)?;
        guard.check()?;
        require_operation_read_pin(current, &c, &guard)?;
        let before = operation_revision(&c)?;
        guard.check()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        guard.check()?;
        validate(&tx, &self.genesis)?;
        guard.check()?;
        let retained = intent::read(&tx)?;
        guard.check()?;
        let terms = retained.terms()?.clone();
        let history_digest = retained.history_digest()?;
        guard.check()?;
        let original_rows_digest = original_rows_digest(&tx)?;
        guard.check()?;
        require_operation_read_pin(current, &tx, &guard)?;
        let custody = OperationCustodyPinV1::capture(self, current, &tx)?;
        guard.check()?;
        let pin = FinancialOperationJournalPinV1 {
            custody,
            retained,
            terms,
            history_digest,
            original_rows_digest,
        };
        if pin.custody.revision != before {
            return Err(JournalError::Conflict);
        }
        pin.require(self, current, &tx)?;
        guard.check()?;
        tx.commit()?;
        guard.check()?;
        if !c.is_autocommit() {
            return Err(JournalError::Conflict);
        }
        pin.require(self, current, &c)?;
        guard.check()?;
        Ok(pin)
    }

    pub(crate) fn check_coordinated_writer_read_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        pin: &FinancialOperationJournalPinV1,
        read: &SignerFinancialWriterReadFinalV1,
    ) -> Result<()> {
        self.check_coordinated_operation_pin_v1(current, pin, OperationObservation::Read(read))
    }

    pub(crate) fn check_coordinated_acquire_arm_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        pin: &FinancialOperationJournalPinV1,
        arm: &SignerAcquireArmV1,
    ) -> Result<()> {
        self.check_coordinated_operation_pin_v1(current, pin, OperationObservation::Arm(arm))
    }

    pub(crate) fn check_coordinated_acquire_final_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        pin: &FinancialOperationJournalPinV1,
        final_action: &SignerAcquireFinalV1,
    ) -> Result<()> {
        self.check_coordinated_operation_pin_v1(
            current,
            pin,
            OperationObservation::Final(final_action),
        )
    }

    fn check_coordinated_operation_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        pin: &FinancialOperationJournalPinV1,
        guard: OperationObservation<'_>,
    ) -> Result<()> {
        guard.check()?;
        let _fence = self
            .journal
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        guard.check()?;
        let mut c = self
            .journal
            .connection
            .lock()
            .map_err(|_| JournalError::Database)?;
        guard.check()?;
        if !c.is_autocommit() {
            return Err(JournalError::Conflict);
        }
        pin.require(self, current, &c)?;
        guard.check()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        guard.check()?;
        let _: i64 = tx.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        guard.check()?;
        pin.require(self, current, &tx)?;
        guard.check()?;
        tx.commit()?;
        guard.check()?;
        if !c.is_autocommit() {
            return Err(JournalError::Conflict);
        }
        pin.require(self, current, &c)?;
        guard.check()
    }
}
