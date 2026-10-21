//! Same-source custody under the distinct post-Acquire Activate Read and Activate.
//! Cached observations authorize nothing; semantic rows are read only by the
//! actual nominal Read. No source guard survives a network or review wait.
use super::*;
use wholepact_financial_coordinator_origin::{
    SignerActivateArmV1, SignerActivateFinalV1, SignerActivatePresentationV1,
    SignerActivateReadFinalV1, SignerContinuePresentationV1,
};

impl PreparedOriginalFinancialSourceV1 {
    fn check_coordinated_activate_read_inputs_v1(
        &self,
        owner_disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        owner_certificate: &str,
        host: &crate::native_peer::PeerProcess,
        read: &SignerActivateReadFinalV1,
    ) -> Result<wholepact_authority::OwnerControlRequest> {
        read.check_current()?;
        let presentation = read.presentation();
        presentation.validate()?;
        let facts = &presentation.facts.original;
        self.require_coordinated_owner_metadata_v2(owner_disclosure, owner_certificate)?;
        let request: wholepact_authority::OwnerControlRequest =
            serde_json::from_str(&facts.continuation_request_json)
                .map_err(|_| Error::InvalidData)?;
        let record = match &request.control {
            wholepact_authority::OwnerControl::AdmitFinancialContinuationV1 { record } => record,
            _ => return Err(Error::ReviewMismatch),
        };
        record
            .validate_request(&request, owner_disclosure)
            .map_err(|_| Error::ReviewMismatch)?;
        if facts.source_identity_digest != self.identity
            || facts.continuation_request_json
                != serde_json::to_string(&request).map_err(|_| Error::InvalidData)?
            || facts.continuation_request_digest
                != SignerContinuePresentationV1::calculate_request_digest(
                    &facts.continuation_request_json,
                )
            || facts.terms_digest
                != record
                    .terms
                    .intent_terms_digest()
                    .map_err(|_| Error::InvalidData)?
            || facts.original_host_process_instance != host.instance()
            || facts.owner_certificate_digest != owner_certificate
            || facts.owner_disclosure_digest
                != wholepact_core::proposal::canonical_digest(
                    "wholepact:coordinated-original-financial-disclosure:v1",
                    owner_disclosure,
                )
                .map_err(|_| Error::InvalidData)?
            || facts.acquired.writer_certificate_digest
                != record.terms.scope.authorization.writer_certificate_digest
            || facts.source_expires_at_ms != self.original_ceiling_ms
            || record.terms.valid_until_ms != self.original_ceiling_ms
            || read.original_writer_session_deadline() > self.original_deadline
            || Instant::now() >= read.original_writer_session_deadline()
            || read.original_source_deadline() != self.original_deadline
            || read.original_read_deadline() > self.original_deadline
            || Instant::now() >= read.original_read_deadline()
        {
            return Err(Error::ReviewMismatch);
        }
        record
            .terms
            .require_live(
                u64::try_from(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| Error::Locked)?
                        .as_millis(),
                )
                .map_err(|_| Error::Locked)?,
            )
            .map_err(|_| Error::Locked)?;
        read.check_current()?;
        self.check_immutable_original_v1()?;
        read.check_current()?;
        host.check_alive()?;
        {
            let held = self.recipient.lock().map_err(|_| Error::Locked)?;
            read.check_current()?;
            let original = held.as_ref().ok_or(Error::Authentication)?;
            if original.instance() != facts.original_host_process_instance {
                return Err(Error::Authentication);
            }
            original.same_live_process(host)?;
            read.check_current()?;
        }
        host.check_alive()?;
        read.check_current()?;
        Ok(request)
    }

    pub(crate) fn prepare_coordinated_activate_read_source_pin_v1(
        &self,
        owner_disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        owner_certificate: &str,
        host: &crate::native_peer::PeerProcess,
        read: &SignerActivateReadFinalV1,
    ) -> Result<FinancialOperationSourcePinV1> {
        let exact = self.check_coordinated_activate_read_inputs_v1(
            owner_disclosure,
            owner_certificate,
            host,
            read,
        )?;
        let journal = {
            let binding = self.financial_binding()?;
            read.check_current()?;
            self.financial_journal()?
                .prepare_coordinated_activate_read_operation_pin_v1(&binding, read)?
        };
        read.check_current()?;
        if journal.continuation_request() != &exact
            || journal.terms().scope.witness != *owner_disclosure
            || journal
                .terms()
                .scope
                .authorization
                .writer_certificate_digest
                != read
                    .presentation()
                    .facts
                    .original
                    .acquired
                    .writer_certificate_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let pin = FinancialOperationSourcePinV1 {
            source_identity: self.identity.clone(),
            operation: FinancialOperationV1::HistoryRead,
            journal,
        };
        self.check_coordinated_activate_read_source_pin_v1(
            &pin,
            owner_disclosure,
            owner_certificate,
            host,
            read,
        )?;
        Ok(pin)
    }

    pub(crate) fn check_coordinated_activate_read_source_pin_v1(
        &self,
        pin: &FinancialOperationSourcePinV1,
        owner_disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        owner_certificate: &str,
        host: &crate::native_peer::PeerProcess,
        read: &SignerActivateReadFinalV1,
    ) -> Result<()> {
        let exact = self.check_coordinated_activate_read_inputs_v1(
            owner_disclosure,
            owner_certificate,
            host,
            read,
        )?;
        if pin.operation != FinancialOperationV1::HistoryRead
            || pin.source_identity != self.identity
            || pin.continuation_request() != &exact
        {
            return Err(Error::ReviewMismatch);
        }
        {
            let binding = self.financial_binding()?;
            read.check_current()?;
            self.financial_journal()?
                .check_coordinated_activate_read_operation_pin_v1(&binding, &pin.journal, read)?;
        }
        read.check_current()?;
        self.check_immutable_original_v1()?;
        read.check_current()?;
        host.check_alive()?;
        read.check_current()?;
        Ok(())
    }
}

impl FinancialOperationSourcePinV1 {
    /// Pure commitment to the actual guarded pin and complete immutable recipe.
    /// Computing this data does not authorize any source read or TLS attempt.
    pub(crate) fn coordinated_activate_ready_digest_v1(
        &self,
        presentation: &SignerActivatePresentationV1,
    ) -> Result<String> {
        presentation.validate()?;
        if self.operation != FinancialOperationV1::Activate
            || self.source_identity != presentation.facts.original.source_identity_digest
            || serde_json::to_string(self.continuation_request()).map_err(|_| Error::InvalidData)?
                != presentation.facts.original.continuation_request_json
        {
            return Err(Error::ReviewMismatch);
        }
        wholepact_core::proposal::canonical_digest(
            "wholepact:coordinated-financial-activate-ready:v1",
            &(
                &self.source_identity,
                &presentation.presentation_digest,
                &presentation.recipe_digest,
                self.journal.coordinated_operation_pin_digest_v1()?,
            ),
        )
        .map_err(|_| Error::InvalidData)
    }
}
impl PreparedOriginalFinancialSourceV1 {
    fn check_coordinated_activate_arm_inputs_v1(
        &self,
        owner_disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        owner_certificate: &str,
        host: &crate::native_peer::PeerProcess,
        arm: &SignerActivateArmV1,
    ) -> Result<wholepact_authority::OwnerControlRequest> {
        arm.check_current()?;
        let presentation = arm.presentation();
        presentation.validate()?;
        let facts = &presentation.facts.original;
        self.require_coordinated_owner_metadata_v2(owner_disclosure, owner_certificate)?;
        let request: wholepact_authority::OwnerControlRequest =
            serde_json::from_str(&facts.continuation_request_json)
                .map_err(|_| Error::InvalidData)?;
        let record = match &request.control {
            wholepact_authority::OwnerControl::AdmitFinancialContinuationV1 { record } => record,
            _ => return Err(Error::ReviewMismatch),
        };
        record
            .validate_request(&request, owner_disclosure)
            .map_err(|_| Error::ReviewMismatch)?;
        if facts.source_identity_digest != self.identity
            || facts.continuation_request_json
                != serde_json::to_string(&request).map_err(|_| Error::InvalidData)?
            || facts.continuation_request_digest
                != SignerContinuePresentationV1::calculate_request_digest(
                    &facts.continuation_request_json,
                )
            || facts.terms_digest
                != record
                    .terms
                    .intent_terms_digest()
                    .map_err(|_| Error::InvalidData)?
            || facts.original_host_process_instance != host.instance()
            || facts.owner_certificate_digest != owner_certificate
            || facts.owner_disclosure_digest
                != wholepact_core::proposal::canonical_digest(
                    "wholepact:coordinated-original-financial-disclosure:v1",
                    owner_disclosure,
                )
                .map_err(|_| Error::InvalidData)?
            || facts.acquired.writer_certificate_digest
                != record.terms.scope.authorization.writer_certificate_digest
            || facts.source_expires_at_ms != self.original_ceiling_ms
            || record.terms.valid_until_ms != self.original_ceiling_ms
            || arm.original_writer_session_deadline() > self.original_deadline
            || Instant::now() >= arm.original_writer_session_deadline()
            || arm.original_source_deadline() != self.original_deadline
            || arm.original_activate_deadline() > self.original_deadline
            || Instant::now() >= arm.original_activate_deadline()
        {
            return Err(Error::ReviewMismatch);
        }
        record
            .terms
            .require_live(
                u64::try_from(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| Error::Locked)?
                        .as_millis(),
                )
                .map_err(|_| Error::Locked)?,
            )
            .map_err(|_| Error::Locked)?;
        arm.check_current()?;
        self.check_immutable_original_v1()?;
        arm.check_current()?;
        host.check_alive()?;
        {
            let held = self.recipient.lock().map_err(|_| Error::Locked)?;
            arm.check_current()?;
            let original = held.as_ref().ok_or(Error::Authentication)?;
            if original.instance() != facts.original_host_process_instance {
                return Err(Error::Authentication);
            }
            original.same_live_process(host)?;
            arm.check_current()?;
        }
        host.check_alive()?;
        arm.check_current()?;
        Ok(request)
    }

    pub(crate) fn prepare_coordinated_activate_source_pin_v1(
        &self,
        owner_disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        owner_certificate: &str,
        host: &crate::native_peer::PeerProcess,
        arm: &SignerActivateArmV1,
    ) -> Result<FinancialOperationSourcePinV1> {
        let exact = self.check_coordinated_activate_arm_inputs_v1(
            owner_disclosure,
            owner_certificate,
            host,
            arm,
        )?;
        let journal = {
            let binding = self.financial_binding()?;
            arm.check_current()?;
            self.financial_journal()?
                .prepare_coordinated_activate_operation_pin_v1(&binding, arm)?
        };
        arm.check_current()?;
        if journal.continuation_request() != &exact
            || journal.terms().scope.witness != *owner_disclosure
            || journal
                .terms()
                .scope
                .authorization
                .writer_certificate_digest
                != arm
                    .presentation()
                    .facts
                    .original
                    .acquired
                    .writer_certificate_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let pin = FinancialOperationSourcePinV1 {
            source_identity: self.identity.clone(),
            operation: FinancialOperationV1::Activate,
            journal,
        };
        self.check_coordinated_activate_arm_source_pin_v1(
            &pin,
            owner_disclosure,
            owner_certificate,
            host,
            arm,
        )?;
        Ok(pin)
    }
    pub(crate) fn check_coordinated_activate_arm_source_pin_v1(
        &self,
        pin: &FinancialOperationSourcePinV1,
        owner_disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        owner_certificate: &str,
        host: &crate::native_peer::PeerProcess,
        arm: &SignerActivateArmV1,
    ) -> Result<()> {
        let exact = self.check_coordinated_activate_arm_inputs_v1(
            owner_disclosure,
            owner_certificate,
            host,
            arm,
        )?;
        if pin.operation != FinancialOperationV1::Activate
            || pin.source_identity != self.identity
            || pin.continuation_request() != &exact
        {
            return Err(Error::ReviewMismatch);
        }
        {
            let binding = self.financial_binding()?;
            arm.check_current()?;
            self.financial_journal()?
                .check_coordinated_activate_arm_operation_pin_v1(&binding, &pin.journal, arm)?;
        }
        arm.check_current()?;
        self.check_immutable_original_v1()?;
        arm.check_current()?;
        host.check_alive()?;
        arm.check_current()?;
        Ok(())
    }
}

// The actual Final checks only the previously Arm-captured operation pin.
// No new source audit, intent read, private preparation or retry is available.
impl PreparedOriginalFinancialSourceV1 {
    fn check_coordinated_activate_final_inputs_v1(
        &self,
        owner_disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        owner_certificate: &str,
        host: &crate::native_peer::PeerProcess,
        final_action: &SignerActivateFinalV1,
    ) -> Result<wholepact_authority::OwnerControlRequest> {
        final_action.check_current()?;
        let presentation = final_action.presentation();
        presentation.validate()?;
        let facts = &presentation.facts.original;
        self.require_coordinated_owner_metadata_v2(owner_disclosure, owner_certificate)?;
        let request: wholepact_authority::OwnerControlRequest =
            serde_json::from_str(&facts.continuation_request_json)
                .map_err(|_| Error::InvalidData)?;
        let record = match &request.control {
            wholepact_authority::OwnerControl::AdmitFinancialContinuationV1 { record } => record,
            _ => return Err(Error::ReviewMismatch),
        };
        record
            .validate_request(&request, owner_disclosure)
            .map_err(|_| Error::ReviewMismatch)?;
        if facts.source_identity_digest != self.identity
            || facts.continuation_request_json
                != serde_json::to_string(&request).map_err(|_| Error::InvalidData)?
            || facts.continuation_request_digest
                != SignerContinuePresentationV1::calculate_request_digest(
                    &facts.continuation_request_json,
                )
            || facts.terms_digest
                != record
                    .terms
                    .intent_terms_digest()
                    .map_err(|_| Error::InvalidData)?
            || facts.original_host_process_instance != host.instance()
            || facts.owner_certificate_digest != owner_certificate
            || facts.owner_disclosure_digest
                != wholepact_core::proposal::canonical_digest(
                    "wholepact:coordinated-original-financial-disclosure:v1",
                    owner_disclosure,
                )
                .map_err(|_| Error::InvalidData)?
            || facts.acquired.writer_certificate_digest
                != record.terms.scope.authorization.writer_certificate_digest
            || facts.source_expires_at_ms != self.original_ceiling_ms
            || record.terms.valid_until_ms != self.original_ceiling_ms
            || final_action.original_writer_session_deadline() > self.original_deadline
            || Instant::now() >= final_action.original_writer_session_deadline()
            || final_action.original_source_deadline() != self.original_deadline
            || final_action.original_activate_deadline() > self.original_deadline
            || Instant::now() >= final_action.original_activate_deadline()
        {
            return Err(Error::ReviewMismatch);
        }
        record
            .terms
            .require_live(
                u64::try_from(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| Error::Locked)?
                        .as_millis(),
                )
                .map_err(|_| Error::Locked)?,
            )
            .map_err(|_| Error::Locked)?;
        final_action.check_current()?;
        self.check_immutable_original_v1()?;
        final_action.check_current()?;
        host.check_alive()?;
        {
            let held = self.recipient.lock().map_err(|_| Error::Locked)?;
            final_action.check_current()?;
            let original = held.as_ref().ok_or(Error::Authentication)?;
            if original.instance() != facts.original_host_process_instance {
                return Err(Error::Authentication);
            }
            original.same_live_process(host)?;
            final_action.check_current()?;
        }
        host.check_alive()?;
        final_action.check_current()?;
        Ok(request)
    }

    pub(crate) fn check_coordinated_activate_final_source_pin_v1(
        &self,
        pin: &FinancialOperationSourcePinV1,
        owner_disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        owner_certificate: &str,
        host: &crate::native_peer::PeerProcess,
        final_action: &SignerActivateFinalV1,
    ) -> Result<()> {
        let exact = self.check_coordinated_activate_final_inputs_v1(
            owner_disclosure,
            owner_certificate,
            host,
            final_action,
        )?;
        if pin.operation != FinancialOperationV1::Activate
            || pin.source_identity != self.identity
            || pin.continuation_request() != &exact
            || pin.coordinated_activate_ready_digest_v1(final_action.presentation())?
                != final_action.activate_ready_digest()
        {
            return Err(Error::ReviewMismatch);
        }
        {
            let binding = self.financial_binding()?;
            final_action.check_current()?;
            self.financial_journal()?
                .check_coordinated_activate_final_operation_pin_v1(
                    &binding,
                    &pin.journal,
                    final_action,
                )?;
        }
        final_action.check_current()?;
        self.check_immutable_original_v1()?;
        final_action.check_current()?;
        host.check_alive()?;
        final_action.check_current()?;
        Ok(())
    }
}
