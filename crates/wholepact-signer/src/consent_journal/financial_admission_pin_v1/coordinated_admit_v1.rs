//! Concrete same-session Admit audit under the coordinated workflow feature.
//! The legacy admission pin bodies remain unchanged. These read-only operations
//! cannot issue an action or authorize transport from cached custody alone.
use super::*;
use wholepact_financial_coordinator_origin::{SignerAdmitArmV1, SignerAdmitFinalV1};

// Closed observations of genuine nominal tokens, never an arbitrary callback.
enum AdmitObservation<'a> {
    Arm(&'a SignerAdmitArmV1),
    Final(&'a SignerAdmitFinalV1),
}
impl AdmitObservation<'_> {
    fn check(&self) -> Result<()> {
        match self {
            Self::Arm(token) => token.check_current(),
            Self::Final(token) => token.check_current(),
        }
        .map_err(|_| JournalError::Permission)
    }
}

// require_pin performs a revision sample before an intent reread. That sample
// may wait inside SQLite, so the genuine Arm must be observed at the internal
// boundary rather than merely before/after the whole legacy helper.
fn require_admit_arm_pin(
    source: &FinancialSourceBindingV1,
    c: &Connection,
    arm: &SignerAdmitArmV1,
) -> Result<()> {
    arm.check_current().map_err(|_| JournalError::Permission)?;
    if source.revision != revision(c)? {
        return Err(JournalError::Conflict);
    }
    arm.check_current().map_err(|_| JournalError::Permission)?;
    if let Some(expected) = &source.continuation_digest {
        let retained = intent::read(c)?;
        arm.check_current().map_err(|_| JournalError::Permission)?;
        if retained.history_digest()? != *expected {
            return Err(JournalError::Conflict);
        }
    }
    arm.check_current().map_err(|_| JournalError::Permission)
}

impl FinancialAdmissionJournalPinV1 {
    /// Ordinary commitment from this actual audited pin only. The private
    /// registration/connection owners remain retained and separately compared;
    /// their pointer addresses are neither serialized nor treated as evidence.
    pub(crate) fn coordinated_admission_pin_digest_v1(&self) -> Result<String> {
        let revision = &self.custody.revision;
        digest(
            "wholepact:coordinated-financial-admission-journal-pin:v1",
            &(
                hex::encode(self.custody.identity.origin_commitment()),
                &self.custody.current_identity,
                &self.custody.pending_identity,
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
    pub(crate) fn prepare_coordinated_admission_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        pending: &PendingFinancialContinuationAdmissionV1,
        arm: &SignerAdmitArmV1,
    ) -> Result<FinancialAdmissionJournalPinV1> {
        let guard = AdmitObservation::Arm(arm);
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
        pending.source.require(&self.journal, &c)?;
        guard.check()?;
        require_admit_arm_pin(current, &c, arm)?;
        guard.check()?;
        require_admit_arm_pin(&pending.source, &c, arm)?;
        guard.check()?;
        let before = admission_revision(&c)?;
        guard.check()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        guard.check()?;
        validate(&tx, &self.genesis)?;
        guard.check()?;
        let retained = intent::read(&tx)?;
        guard.check()?;
        if retained != pending.retained {
            return Err(JournalError::Conflict);
        }
        let history_digest = retained.history_digest()?;
        guard.check()?;
        let original_rows_digest = original_rows_digest(&tx)?;
        guard.check()?;
        require_admit_arm_pin(current, &tx, arm)?;
        guard.check()?;
        require_admit_arm_pin(&pending.source, &tx, arm)?;
        guard.check()?;
        let custody = AdmissionCustodyPinV1::capture(self, current, &pending.source, &tx)?;
        guard.check()?;
        let pin = FinancialAdmissionJournalPinV1 {
            custody,
            retained,
            history_digest,
            original_rows_digest,
        };
        if pin.custody.revision != before {
            return Err(JournalError::Conflict);
        }
        pin.require(self, current, pending, &tx)?;
        guard.check()?;
        tx.commit()?;
        guard.check()?;
        if !c.is_autocommit() {
            return Err(JournalError::Conflict);
        }
        pin.require(self, current, pending, &c)?;
        guard.check()?;
        Ok(pin)
    }

    pub(crate) fn check_coordinated_admission_arm_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        pending: &PendingFinancialContinuationAdmissionV1,
        pin: &FinancialAdmissionJournalPinV1,
        arm: &SignerAdmitArmV1,
    ) -> Result<()> {
        self.check_coordinated_admission_pin_v1(current, pending, pin, AdmitObservation::Arm(arm))
    }

    pub(crate) fn check_coordinated_admission_final_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        pending: &PendingFinancialContinuationAdmissionV1,
        pin: &FinancialAdmissionJournalPinV1,
        final_action: &SignerAdmitFinalV1,
    ) -> Result<()> {
        self.check_coordinated_admission_pin_v1(
            current,
            pending,
            pin,
            AdmitObservation::Final(final_action),
        )
    }

    /// Same maintained metadata/revision sample. No intent/semantic replay and
    /// no connection, fence or read transaction survives this call into I/O.
    fn check_coordinated_admission_pin_v1(
        &self,
        current: &FinancialSourceBindingV1,
        pending: &PendingFinancialContinuationAdmissionV1,
        pin: &FinancialAdmissionJournalPinV1,
        guard: AdmitObservation<'_>,
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
        pin.require(self, current, pending, &c)?;
        guard.check()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        guard.check()?;
        let _: i64 = tx.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        guard.check()?;
        pin.require(self, current, pending, &tx)?;
        guard.check()?;
        tx.commit()?;
        guard.check()?;
        if !c.is_autocommit() {
            return Err(JournalError::Conflict);
        }
        pin.require(self, current, pending, &c)?;
        guard.check()
    }
}
