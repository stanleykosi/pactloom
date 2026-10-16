//! Issuance lives inside the sealed consent module. Native grant decisions and
//! independently verified exact automatic continuations are separate types.
use super::*;
use crate::consent_journal::automation;
use wholepact_core::automation::{AutomationAccountPolicy, AutomationGrantTerms};

pub struct PreparedAutomationGrantChange(Pending<NativeAutomationGrantRecord>);
pub struct ApprovedAutomationGrantChange(
    pub(in crate::consent_journal) Approval<NativeAutomationGrantRecord>,
);
impl PreparedAutomationGrantChange {
    pub fn record(&self) -> &NativeAutomationGrantRecord {
        &self.0.record
    }
    pub fn review_digest(&self) -> &str {
        &self.0.review_digest
    }
    pub fn display(&self) -> Result<String> {
        Ok(format!(
            "Bounded automatic authorization\n\n{}\n\nApprove this explicit application, enrollment, epoch, recipient, fee, evidence and time scope. Automatic requests still require exact artifact verification and a current independent witness admission. The grant outstanding limit is separate from the witness settled-plus-pending lifetime debit ceiling. Pause/revoke stops new admissions; earlier exact admitted key use and released signatures may still execute. This does not authorize automatic disclosure, export or dispatch. Restored grants cannot activate in a successor epoch.",
            serde_json::to_string_pretty(&self.0.record)
                .map_err(|_| JournalError::InvalidBinding)?
        ))
    }
}
impl ApprovedAutomationGrantChange {
    pub fn record(&self) -> &NativeAutomationGrantRecord {
        &self.0.record
    }
}
impl SignerConsentSession {
    pub fn prepare_automation_grant(
        &self,
        journal: &SignerConsentJournal,
        enrollment: &AccountEnrollmentRecord,
        policy: AutomationAccountPolicy,
        terms: AutomationGrantTerms,
        witness: SponsorWitnessBinding,
        status: AutomationGrantStatus,
    ) -> Result<PreparedAutomationGrantChange> {
        enrollment.validate()?;
        // A fresh native owner may reduce a retained same-epoch grant after
        // restart. Activation/renewal still requires this exact live enrollment.
        if status == AutomationGrantStatus::Active {
            self.matches(enrollment)?;
        }
        let receipt = self.receipt()?;
        let account = journal.account_state()?;
        let permission = self.read_lease(&journal.binding(), &account)?;
        let _fence = journal
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let c = journal
            .connection
            .lock()
            .map_err(|_| JournalError::Database)?;
        storage::check_account(&c, &account)?;
        if storage::read_enrollment(&c, enrollment.reference())?.as_ref() != Some(enrollment) {
            return Err(JournalError::Permission);
        }
        let old = automation::read_current(&c, &terms.grant_id)?;
        let revision = old
            .as_ref()
            .map_or(Some(1), |o| o.binding.revision.checked_add(1))
            .ok_or(JournalError::Limit)?;
        let binding = AutomationGrantBinding {
            grant_id: terms.grant_id.clone(),
            application_id: terms.application_id.clone(),
            revision,
            terms_digest: digest(
                "wholepact:native-automation-grant-terms:v1",
                &(&policy, &terms, enrollment.reference(), &witness),
            )?,
        };
        let record = NativeAutomationGrantRecord {
            binding,
            policy,
            terms,
            witness,
            enrollment_ref: enrollment.reference().into(),
            status,
            principal_id: self.inner.principal_id.clone(),
            receipt,
        };
        automation::validate_enrollment(&record, enrollment, &account, permission.principal)?;
        automation::validate_transition(old.as_ref(), &record)?;
        automation::validate_account_policy(&c, &record.policy)?;
        if status == AutomationGrantStatus::Active {
            record.require_active(now_ms()?)?;
        }
        let review = record.reference()?;
        Ok(PreparedAutomationGrantChange(Pending::new(
            record,
            review,
            &self.inner,
        )))
    }
    pub fn approve_automation_grant(
        &self,
        prepared: PreparedAutomationGrantChange,
        decision: NativeConsentDecision,
    ) -> Result<ApprovedAutomationGrantChange> {
        Ok(ApprovedAutomationGrantChange(
            prepared.0.approve(self, decision)?,
        ))
    }
}

/// No public constructor or deserialization. An exact verifier result and native
/// grant are required; this cannot convert into manual NativeConsentDecision.
pub struct ApprovedAutomaticSpendConsent(
    pub(in crate::consent_journal) Approval<OriginalSpendConsent>,
);
impl ApprovedAutomaticSpendConsent {
    pub fn record(&self) -> &OriginalSpendConsent {
        &self.0.record
    }
    pub(in crate::consent_journal) fn continuation(&self) -> ApprovedAutomaticContinuation {
        ApprovedAutomaticContinuation {
            session: Arc::clone(&self.0.session),
            created: self.0.created,
            consent: self.0.record.clone(),
        }
    }
}
/// Ephemeral exact continuation; retained JSON and a prior reservation cannot
/// reconstruct it. Cloning is private and only used to keep a held lease alive.
pub struct ApprovedAutomaticContinuation {
    session: Arc<SessionInner>,
    created: Instant,
    consent: OriginalSpendConsent,
}
impl ApprovedAutomaticContinuation {
    pub(in crate::consent_journal) fn clone_for_lease(&self) -> Self {
        Self {
            session: Arc::clone(&self.session),
            created: self.created,
            consent: self.consent.clone(),
        }
    }
    pub(in crate::consent_journal) fn matches(
        &self,
        session: &SignerConsentSession,
        consent: &OriginalSpendConsent,
        permission: &ReadLease<'_>,
    ) -> Result<()> {
        if !Arc::ptr_eq(&self.session, &session.inner)
            || &self.consent != consent
            || consent.terms.automation.is_none()
        {
            return Err(JournalError::Permission);
        }
        self.check_current_held(permission)
    }
    pub(in crate::consent_journal) fn check_current(&self) -> Result<()> {
        let state = self.session.read()?;
        self.check_deadline(state.generation)
    }
    pub(in crate::consent_journal) fn check_current_held(
        &self,
        permission: &ReadLease<'_>,
    ) -> Result<()> {
        permission.check_current()?;
        if !std::ptr::eq(permission.session, self.session.as_ref()) {
            return Err(JournalError::Permission);
        }
        self.check_deadline(permission._guard.generation)
    }
    fn check_deadline(&self, generation: u64) -> Result<()> {
        let binding = self
            .consent
            .terms
            .automation
            .as_ref()
            .ok_or(JournalError::Permission)?;
        let receipt = &self.consent.terms.receipt;
        let now = now_ms()?;
        let window = binding
            .authorization_expires_at_ms
            .checked_sub(receipt.reviewed_at_ms)
            .ok_or(JournalError::Expired)?;
        if self.created.elapsed() >= Duration::from_secs(120)
            || self.created.elapsed() >= Duration::from_millis(window)
            || now < receipt.reviewed_at_ms
            || now >= receipt.expires_at_ms
            || now >= binding.authorization_expires_at_ms
            || receipt.writer_epoch != self.session.writer_epoch
            || receipt.native_session_id != self.session.session_id
            || receipt.permission_generation != generation
        {
            return Err(JournalError::Expired);
        }
        Ok(())
    }
}

#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
impl SignerConsentSession {
    pub(crate) fn derive_automatic_spend(
        &self,
        journal: &SignerConsentJournal,
        prepared: PreparedSpendConsent,
        grant: &NativeAutomationGrantRecord,
        verified: &crate::authority_bridge::automation::VerifiedAutomaticRequest,
    ) -> Result<ApprovedAutomaticSpendConsent> {
        verified
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        let request = verified.request();
        if prepared.record().reference() != verified.original_consent_reference()
            || prepared.record().terms().automation.is_some()
            || !Arc::ptr_eq(&prepared.0.session, &self.inner)
            || prepared.0.created.elapsed() >= Duration::from_secs(120)
        {
            return Err(JournalError::Permission);
        }
        let account = journal.account_state()?;
        let permission = self.read_lease(&journal.binding(), &account)?;
        let _fence = journal
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let c = journal
            .connection
            .lock()
            .map_err(|_| JournalError::Database)?;
        storage::check_account(&c, &account)?;
        if automation::read_current(&c, &grant.binding.grant_id)?.as_ref() != Some(grant) {
            return Err(JournalError::Permission);
        }
        let enrollment =
            storage::read_enrollment(&c, &grant.enrollment_ref)?.ok_or(JournalError::Permission)?;
        automation::validate_enrollment(grant, &enrollment, &account, permission.principal)?;
        grant.require_active(now_ms()?)?;
        wholepact_core::automation::evaluate_automation_request(
            &grant.policy,
            &grant.terms,
            request,
            now_ms()?,
        )
        .map_err(|_| JournalError::InvalidBinding)?;
        let t = prepared.record().terms();
        let inputs: Vec<String> = t
            .input_bindings
            .iter()
            .map(|i| i.input_id.clone())
            .collect();
        if request.authorization_id != t.authorization_id
            || request.account_id != t.account_id
            || request.writer_epoch != t.receipt.writer_epoch
            || request.application_id != grant.binding.application_id
            || request.agreement_id != t.agreement_id
            || request.obligation_id != t.obligation_id
            || request.proposal_id != t.proposal_id
            || request.manifest_digest != t.manifest_digest
            || request.effects_digest != t.effects_digest
            || request.artifact_digest != t.artifact_digest
            || request.maximum_debit.as_zatoshis() != t.maximum_debit_zatoshis
            || request.fee.as_zatoshis() != t.fee_share_zatoshis
            || request.input_ids != inputs
            || request.current_height != t.wallet_snapshot.tip_height
            || request.transaction_expiry_height != t.transaction_expiry_height
            || t.enrollment_ref != grant.enrollment_ref
            || t.principal_id != grant.principal_id
        {
            return Err(JournalError::InvalidBinding);
        }
        sponsor::current_for_consent(&c, t)?;
        let mut terms = prepared.0.record.terms;
        terms.automation = Some(AutomationConsentBinding {
            grant: grant.binding.clone(),
            request_digest: digest("wholepact:verified-automatic-request:v1", request)?,
            authorization_expires_at_ms: request.authorization_expires_at_ms,
        });
        let record = OriginalSpendConsent::new(terms)?;
        verified
            .check_current()
            .map_err(|_| JournalError::Permission)?;
        permission.check_current()?;
        Ok(ApprovedAutomaticSpendConsent(Approval {
            record,
            session: prepared.0.session,
            created: prepared.0.created,
        }))
    }
}

#[cfg(test)]
pub(in crate::consent_journal) fn synthetic_automatic_spend(
    session: &SignerConsentSession,
    mut terms: SpendConsentTerms,
    grant: &NativeAutomationGrantRecord,
) -> ApprovedAutomaticSpendConsent {
    terms.automation = Some(AutomationConsentBinding {
        grant: grant.binding.clone(),
        request_digest: "d4".repeat(32),
        authorization_expires_at_ms: now_ms().unwrap() + 60_000,
    });
    terms.receipt = session.receipt().unwrap();
    ApprovedAutomaticSpendConsent(Approval {
        record: OriginalSpendConsent::new(terms).unwrap(),
        session: Arc::clone(&session.inner),
        created: Instant::now(),
    })
}
