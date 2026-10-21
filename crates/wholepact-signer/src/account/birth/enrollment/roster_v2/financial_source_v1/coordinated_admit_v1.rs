//! Concrete same-source Admit custody for one retained coordinated role.
//! Actual source, owner and Host remain separately retained. No native owner
//! conversion, private pre-review audit, retry or replacement source.
use super::*;
use wholepact_financial_coordinator_origin::{
    SignerAdmitArmV1, SignerAdmitFinalV1, SignerAdmitPresentationV1, SignerContinuePresentationV1,
};

enum AdmitObservation<'a> {
    Arm(&'a SignerAdmitArmV1),
    Final(&'a SignerAdmitFinalV1),
}
impl AdmitObservation<'_> {
    fn check(&self) -> Result<()> {
        match self {
            Self::Arm(token) => token.check_current(),
            Self::Final(token) => token.check_current(),
        }?;
        Ok(())
    }
    fn presentation(&self) -> &SignerAdmitPresentationV1 {
        match self {
            Self::Arm(token) => token.presentation(),
            Self::Final(token) => token.presentation(),
        }
    }
    fn original_source_deadline(&self) -> Instant {
        match self {
            Self::Arm(token) => token.original_source_deadline(),
            Self::Final(token) => token.original_source_deadline(),
        }
    }
    fn original_admit_deadline(&self) -> Instant {
        match self {
            Self::Arm(token) => token.original_admit_deadline(),
            Self::Final(token) => token.original_admit_deadline(),
        }
    }
}

impl FinancialAdmissionSourcePinV1 {
    /// Exact ordinary Ready commitment derived from this actual audited pin.
    /// This cannot mint an Arm/Final or reconstruct its private source owners.
    pub(crate) fn coordinated_admission_ready_digest_v1(
        &self,
        presentation_digest: &str,
    ) -> Result<String> {
        wholepact_core::proposal::canonical_digest(
            "wholepact:coordinated-financial-admission-ready:v1",
            &(
                presentation_digest,
                &self.source_identity,
                &self.admission_terms_digest,
                &self.disclosure,
                &self.certificate_digest,
                self.journal.coordinated_admission_pin_digest_v1()?,
            ),
        )
        .map_err(|_| Error::InvalidData)
    }
}

impl PreparedOriginalFinancialSourceV1 {
    fn check_coordinated_admit_inputs_v1(
        &self,
        pending: &PendingFinancialContinuationAdmissionV1,
        disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        certificate: &str,
        host: &crate::native_peer::PeerProcess,
        guard: &AdmitObservation<'_>,
    ) -> Result<()> {
        guard.check()?;
        let presentation = guard.presentation();
        presentation.validate()?;
        let facts = &presentation.facts;
        self.require_coordinated_owner_metadata_v2(disclosure, certificate)?;
        let request = pending.request();
        let request_json = serde_json::to_string(request).map_err(|_| Error::InvalidData)?;
        let record = match &request.control {
            wholepact_authority::OwnerControl::AdmitFinancialContinuationV1 { record } => record,
            _ => return Err(Error::ReviewMismatch),
        };
        record
            .validate_request(request, disclosure)
            .map_err(|_| Error::ReviewMismatch)?;
        if facts.source_identity_digest != self.identity
            || facts.admission_terms_digest != pending.admission_terms_digest(&self.identity)?
            || facts.request_json != request_json
            || facts.request_digest
                != SignerContinuePresentationV1::calculate_request_digest(&request_json)
            || facts.original_host_process_instance != host.instance()
            || facts.owner_certificate_digest != certificate
            || facts.disclosure_json
                != serde_json::to_string(disclosure).map_err(|_| Error::InvalidData)?
            || facts.disclosure_digest
                != wholepact_core::proposal::canonical_digest(
                    "wholepact:coordinated-original-financial-disclosure:v1",
                    disclosure,
                )
                .map_err(|_| Error::InvalidData)?
            || facts.account_id != request.account_id
            || facts.network_profile_id != request.network_profile_id
            || facts.operation_id != request.operation_id
            || facts.expected_head_sequence != request.expected_head.sequence
            || facts.expected_head_digest != request.expected_head.digest
            || facts.terms_digest
                != record
                    .terms
                    .intent_terms_digest()
                    .map_err(|_| Error::InvalidData)?
            || facts.source_expires_at_ms != self.original_ceiling_ms
            || record.terms.valid_until_ms != self.original_ceiling_ms
            || guard.original_source_deadline() != self.original_deadline
            || guard.original_admit_deadline() > self.original_deadline
            || Instant::now() >= guard.original_admit_deadline()
        {
            return Err(Error::ReviewMismatch);
        }
        // Metadata-only original source checks. The actual private audit is
        // performed by the concrete Arm journal entry below, never custody.
        guard.check()?;
        self.check_immutable_original_v1()?;
        guard.check()?;
        host.check_alive()?;
        {
            let held = self.recipient.lock().map_err(|_| Error::Locked)?;
            guard.check()?;
            let original = held.as_ref().ok_or(Error::Authentication)?;
            if original.instance() != facts.original_host_process_instance {
                return Err(Error::Authentication);
            }
            original.same_live_process(host)?;
            guard.check()?;
        }
        host.check_alive()?;
        guard.check()
    }

    pub(crate) fn prepare_coordinated_admission_source_pin_v1(
        &self,
        pending: &PendingFinancialContinuationAdmissionV1,
        disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        certificate: &str,
        host: &crate::native_peer::PeerProcess,
        arm: &SignerAdmitArmV1,
    ) -> Result<FinancialAdmissionSourcePinV1> {
        let guard = AdmitObservation::Arm(arm);
        self.check_coordinated_admit_inputs_v1(pending, disclosure, certificate, host, &guard)?;
        let admission_terms_digest = pending.admission_terms_digest(self.identity_digest())?;
        let journal = {
            let binding = self.financial_binding()?;
            guard.check()?;
            self.financial_journal()?
                .prepare_coordinated_admission_pin_v1(&binding, pending, arm)?
        };
        guard.check()?;
        let pin = FinancialAdmissionSourcePinV1 {
            source_identity: self.identity.clone(),
            journal,
            disclosure: disclosure.clone(),
            certificate_digest: certificate.to_owned(),
            admission_terms_digest,
        };
        self.check_coordinated_admit_inputs_v1(pending, disclosure, certificate, host, &guard)?;
        {
            let binding = self.financial_binding()?;
            guard.check()?;
            self.financial_journal()?
                .check_coordinated_admission_arm_pin_v1(&binding, pending, &pin.journal, arm)?;
        }
        guard.check()?;
        self.check_immutable_original_v1()?;
        guard.check()?;
        Ok(pin)
    }

    pub(crate) fn check_coordinated_admission_source_pin_v1(
        &self,
        pin: &FinancialAdmissionSourcePinV1,
        pending: &PendingFinancialContinuationAdmissionV1,
        disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        certificate: &str,
        host: &crate::native_peer::PeerProcess,
        final_action: &SignerAdmitFinalV1,
    ) -> Result<()> {
        let guard = AdmitObservation::Final(final_action);
        self.check_coordinated_admit_inputs_v1(pending, disclosure, certificate, host, &guard)?;
        if self.identity != pin.source_identity
            || disclosure != &pin.disclosure
            || certificate != pin.certificate_digest
            || pin.admission_terms_digest
                != final_action.presentation().facts.admission_terms_digest
            || pin.coordinated_admission_ready_digest_v1(
                &final_action.presentation().presentation_digest,
            )? != final_action.admission_ready_digest()
        {
            return Err(Error::ReviewMismatch);
        }
        {
            let binding = self.financial_binding()?;
            guard.check()?;
            self.financial_journal()?
                .check_coordinated_admission_final_pin_v1(
                    &binding,
                    pending,
                    &pin.journal,
                    final_action,
                )?;
        }
        guard.check()?;
        self.check_immutable_original_v1()?;
        guard.check()?;
        host.check_alive()?;
        guard.check()
    }
}
