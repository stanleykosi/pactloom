//! Finite synthetic roster phases through the actual native Window controller.
//! Inputs and outputs are inert signed/public evidence. The retained concrete
//! installation and real native review, never these DTOs, authorize publication.
use super::*;
use crate::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2;
use crate::manual_roster_witness_v2::ManualRosterAttemptObservationV2;

const EXTENSION: &str = "Authenticate signed V2 Host roster extension for review";
const CONTINUATION: &str = "Authenticate signed V2 Host roster continuation for review";

/// Read back from the actual immutable journal after native publication. This
/// value has no native owner, session, lease or construction capability.
pub struct EphemeralRosterAttemptV2 {
    pub extension: ManualRosterEnrollmentExtensionV2,
    pub attempt: ManualRosterAttemptObservationV2,
}
impl EphemeralNativeWitnessV1 {
    /// Read the actual immutable original/latest attempt solely to coordinate
    /// the temporary fixture's wait for its real prior publication deadline.
    /// This inert observation creates no native owner, grant or continuation.
    pub fn observe_original_roster_attempt_v2(
        &mut self,
        account_id: &str,
    ) -> Result<EphemeralRosterAttemptV2> {
        self.original_roster_attempt(account_id)
    }

    pub fn review_original_roster_extension_v2(
        &mut self,
        account_id: &str,
        signed_export: &[u8],
    ) -> Result<EphemeralRosterAttemptV2> {
        self.select_original_signed_form(account_id, signed_export)?;
        self.window.input.signed_manual_roster_extension_json = Zeroizing::new(
            std::str::from_utf8(signed_export)
                .map_err(|_| AuthorityError::InvalidBinding)?
                .into(),
        );
        self.click(EXTENSION)?;
        self.drain()?;
        if !matches!(
            self.window.pending.as_ref().map(|p| &p.prepared.proposal),
            Some(Proposal::ManualRosterExtensionV2(_))
        ) {
            return Err(AuthorityError::Permission);
        }
        self.approve_exact()?;
        let original = self.original_roster_attempt(account_id)?;
        let expected: crate::manual_roster_signature_v2::ManualRosterEnrollmentOwnerSignatureV2 =
            serde_json::from_slice(signed_export).map_err(|_| AuthorityError::InvalidBinding)?;
        if original.extension != expected.extension {
            return Err(AuthorityError::CorruptHistory);
        }
        self.completed_native_receipt()?;
        Ok(original)
    }

    pub fn review_original_roster_continuation_v2(
        &mut self,
        account_id: &str,
        signed_export: &[u8],
    ) -> Result<EphemeralRosterAttemptV2> {
        self.select_original_signed_form(account_id, signed_export)?;
        self.window.input.signed_manual_roster_continuation_json = Zeroizing::new(
            std::str::from_utf8(signed_export)
                .map_err(|_| AuthorityError::InvalidBinding)?
                .into(),
        );
        self.click(CONTINUATION)?;
        self.drain()?;
        if !matches!(
            self.window.pending.as_ref().map(|p| &p.prepared.proposal),
            Some(Proposal::ManualRosterContinuationV2(_))
        ) {
            return Err(AuthorityError::Permission);
        }
        self.approve_exact()?;
        let original = self.original_roster_attempt(account_id)?;
        let expected: crate::manual_roster_continuation_signature_v2::ManualRosterContinuationOwnerSignatureV2 =
            serde_json::from_slice(signed_export).map_err(|_| AuthorityError::InvalidBinding)?;
        if original.extension != expected.extension
            || original.attempt.attempt_digest
                != expected.continuation.digest_for(&expected.extension)?
        {
            return Err(AuthorityError::CorruptHistory);
        }
        self.completed_native_receipt()?;
        Ok(original)
    }

    /// Selects only the exact retained native-published attempt. The shared
    /// production inner opener verifies original namespace, extension, current
    /// attempt and expiry before the maintained TLS server receives any request.
    pub fn serve_original_roster_attempt_v2(
        &mut self,
        account_id: &str,
        extension_digest: &str,
        attempt_digest: &str,
    ) -> Result<EphemeralHistoryServerV1> {
        let input = self.original_namespace_input(account_id)?;
        let actual_listen = self
            .listener
            .local_addr()
            .map_err(|_| AuthorityError::Storage)?
            .to_string();
        let journal =
            crate::born_history_server::open_born_manual_roster_attempt_v2_from_namespace(
                input,
                extension_digest,
                attempt_digest,
                &self.server_certificate_digest,
                &actual_listen,
            )?;
        self.serve_exact_server(AuthorityServer::new(Arc::new(journal), self.tls.clone()))
    }

    pub fn review_original_construction_plan_v3(
        &mut self,
        account_id: &str,
        signed_export: &[u8],
    ) -> Result<String> {
        use super::super::synthetic_plan_diagnostics_v1::{self as diagnostic, Boundary as B};
        diagnostic::input_size(signed_export);
        diagnostic::run(B::WitnessPlanSelect, || {
            self.select_original_signed_form(account_id, signed_export)
        })?;
        self.window.input.signed_manual_roster_construction_v3_json = Zeroizing::new(
            diagnostic::run(B::WitnessPlanInputUtf8, || {
                std::str::from_utf8(signed_export).map_err(|_| AuthorityError::InvalidBinding)
            })?
            .into(),
        );
        diagnostic::run(B::WitnessPlanPublicRefusal, || {
            self.require_public_v3_refusal(
                "Authenticate signed V3 non-signing construction plan for review",
            )
        })?;
        diagnostic::run(B::WitnessPlanQualifiedEntry, || {
            self.click_qualified_entry(QualifiedEntry::ConstructionPlan)
        })?;
        diagnostic::run(B::WitnessPlanDrain, || self.drain())?;
        diagnostic::run(B::WitnessPlanPending, || {
            if !matches!(
                self.window.pending.as_ref().map(|p| &p.prepared.proposal),
                Some(Proposal::ManualRosterConstructionV3(_))
            ) {
                return Err(AuthorityError::Permission);
            }
            Ok(())
        })?;
        diagnostic::run(B::WitnessPlanApprove, || self.approve_exact())?;
        let receipt = diagnostic::run(B::WitnessPlanReceipt, || self.completed_native_receipt())?;
        let actual = diagnostic::run(B::WitnessPlanReceiptDigest, || {
            receipt
                .get("approval_digest")
                .and_then(serde_json::Value::as_str)
                .ok_or(AuthorityError::CorruptHistory)
        })?;
        let expected: crate::manual_roster_construction_v3::ManualRosterConstructionOwnerSignatureV3 =
            diagnostic::run(B::WitnessPlanExpectedParse, || {
                serde_json::from_slice(signed_export).map_err(|_| AuthorityError::InvalidBinding)
            })?;
        diagnostic::run(B::WitnessPlanDigestMatch, || {
            if actual != expected.approval.digest_for(&expected.extension)? {
                return Err(AuthorityError::CorruptHistory);
            }
            Ok(())
        })?;
        Ok(actual.into())
    }

    pub fn review_original_construction_handoff_v1(
        &mut self,
        account_id: &str,
        signed_export: &[u8],
    ) -> Result<crate::construction_transport_handoff_v1::PendingConstructionTransportGrantV1> {
        self.select_original_signed_form(account_id, signed_export)?;
        self.window
            .input
            .signed_construction_transport_preauthorization_json = Zeroizing::new(
            std::str::from_utf8(signed_export)
                .map_err(|_| AuthorityError::InvalidBinding)?
                .into(),
        );
        self.require_public_v3_refusal(
            "Authenticate original-owner handoff admission for exact review",
        )?;
        self.click_qualified_entry(QualifiedEntry::ConstructionTransport)?;
        self.drain()?;
        if !matches!(
            self.window.pending.as_ref().map(|p| &p.prepared.proposal),
            Some(Proposal::ConstructionTransportGrantV1(_))
        ) {
            return Err(AuthorityError::Permission);
        }
        self.approve_exact()?;
        let receipt = self.completed_native_receipt()?;
        let pending: crate::construction_transport_handoff_v1::PendingConstructionTransportGrantV1 =
            serde_json::from_value(
                receipt
                    .get("pending_grant")
                    .cloned()
                    .ok_or(AuthorityError::CorruptHistory)?,
            )
            .map_err(|_| AuthorityError::CorruptHistory)?;
        let journal =
            crate::witness_locator::open_born_history(self.original_namespace_input(account_id)?)?;
        let connection = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(connection.connection())?;
        if ledger.construction_transport_grant(&pending.digest()?)? != pending {
            return Err(AuthorityError::CorruptHistory);
        }
        Ok(pending)
    }

    pub fn serve_original_construction_handoff_v1(
        &mut self,
        account_id: &str,
        extension_digest: &str,
        attempt_digest: &str,
        pending_grant_digest: &str,
    ) -> Result<EphemeralHistoryServerV1> {
        let input = self.original_namespace_input(account_id)?;
        let actual_listen = self
            .listener
            .local_addr()
            .map_err(|_| AuthorityError::Storage)?
            .to_string();
        let journal =
            crate::born_history_server::open_born_manual_roster_attempt_v2_from_namespace(
                input,
                extension_digest,
                attempt_digest,
                &self.server_certificate_digest,
                &actual_listen,
            )?;
        let journal = Arc::new(journal);
        if !matches!(
            AuthorityServer::for_construction_transport_v1(
                journal.clone(),
                self.tls.clone(),
                pending_grant_digest,
            ),
            Err(AuthorityError::ConstructionHistoryUnsupported)
        ) {
            return Err(AuthorityError::Conflict);
        }
        let server = AuthorityServer::for_retained_construction_transport_v1(
            journal,
            self.tls.clone(),
            pending_grant_digest,
        )?;
        self.serve_exact_server(server)
    }

    fn require_public_v3_refusal(&mut self, label: &str) -> Result<()> {
        // The negative public-control test must not hide a stale injected entry.
        if self.qualification_entry.is_some() {
            return Err(AuthorityError::Conflict);
        }
        public_control_navigation_v1::require_refusal(&mut self.window, &self.context, label)
    }

    pub(super) fn completed_native_receipt(&self) -> Result<serde_json::Value> {
        let (clock, display) = self
            .window
            .last_archive_receipt
            .as_ref()
            .ok_or(AuthorityError::Uncertain)?;
        clock.check()?;
        serde_json::from_str(display).map_err(|_| AuthorityError::CorruptHistory)
    }

    pub(super) fn select_original_signed_form(
        &mut self,
        account_id: &str,
        signed_export: &[u8],
    ) -> Result<()> {
        if !self.window.can_select()
            || signed_export.is_empty()
            || signed_export.len() > crate::MAX_FRAME_BYTES
        {
            return Err(AuthorityError::Permission);
        }
        // Reselect the same independently retained public certificate after the
        // preceding operation intentionally cleared all raw input fields.
        self.original_namespace_input(account_id)?;
        Ok(())
    }

    fn original_roster_attempt(&mut self, account_id: &str) -> Result<EphemeralRosterAttemptV2> {
        let journal =
            crate::witness_locator::open_born_history(self.original_namespace_input(account_id)?)?;
        journal.require_born_read_current()?;
        let connection = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(connection.connection())?;
        ledger.require_supported_manual_history()?;
        let extension = ledger
            .manual_roster_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension
            .clone();
        let attempt = ledger.latest_manual_roster_attempt_v2()?;
        journal.require_born_read_current()?;
        Ok(EphemeralRosterAttemptV2 { extension, attempt })
    }
}
