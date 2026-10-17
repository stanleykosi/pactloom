//! Actual first-account native extension and original-attempt selection.
//! Synthetic controller delivery only; no enrollment or predecessor is seeded.
use super::*;
use crate::manual_enrollment::ManualEnrollmentExtension;

impl EphemeralNativeWitnessV1 {
    pub fn review_original_single_extension_v1(
        &mut self,
        account_id: &str,
        signed_export: &[u8],
    ) -> Result<ManualEnrollmentExtension> {
        self.select_original_signed_form(account_id, signed_export)?;
        self.window.input.signed_manual_extension_json = Zeroizing::new(
            std::str::from_utf8(signed_export)
                .map_err(|_| AuthorityError::InvalidBinding)?
                .into(),
        );
        self.click("Authenticate exact signed manual extension for review")?;
        self.drain()?;
        if !matches!(
            self.window.pending.as_ref().map(|p| &p.prepared.proposal),
            Some(Proposal::ManualExtension(_))
        ) {
            return Err(AuthorityError::Permission);
        }
        self.approve_exact()?;
        let journal =
            crate::witness_locator::open_born_history(self.original_namespace_input(account_id)?)?;
        journal.require_born_read_current()?;
        let connection = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(connection.connection())?;
        let extension = ledger
            .manual_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension
            .clone();
        let expected: crate::manual_enrollment_signature::ManualEnrollmentExtensionOwnerSignature =
            serde_json::from_slice(signed_export).map_err(|_| AuthorityError::InvalidBinding)?;
        if extension != expected.extension {
            return Err(AuthorityError::CorruptHistory);
        }
        journal.require_born_read_current()?;
        self.completed_native_receipt()?;
        Ok(extension)
    }

    pub fn serve_original_single_attempt_v1(
        &mut self,
        account_id: &str,
        extension_digest: &str,
    ) -> Result<EphemeralHistoryServerV1> {
        let input = self.original_namespace_input(account_id)?;
        let actual_listen = self
            .listener
            .local_addr()
            .map_err(|_| AuthorityError::Storage)?
            .to_string();
        let journal = crate::born_history_server::open_born_manual_attempt_from_namespace(
            input,
            extension_digest,
            None,
            &self.server_certificate_digest,
            &actual_listen,
        )?;
        self.serve_exact_server(AuthorityServer::new(Arc::new(journal), self.tls.clone()))
    }
}
