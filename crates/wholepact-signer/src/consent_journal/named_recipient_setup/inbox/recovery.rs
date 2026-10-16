//! Read-only reopening after an uncertain import. This exact original path does
//! not retry insertion, renew validity, create a new sequence or authorize use.
use super::*;
use wholepact_offline_bridge::recover_named_verifier_assertion_bound;
use wholepact_transport::SignerNamedRecipientReceiptSource;

impl LiveNamedRecipientProfile {
    /// The caller keeps the same original reference and ciphertext digest after
    /// ImportCommittedButUnavailable. None means no matching durable receipt was
    /// observed; it does not establish that a different submission is safe.
    /// Only a genuine current native profile/session can enter this owner path.
    pub(crate) fn recover_assertion_import(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        original_ref: &str,
        own_policy: &OwnEffectsPolicy,
        exact_envelope_digest: &str,
    ) -> ImportResult<Option<ReceivedNamedVerifierAssertion>> {
        require_profile_owner(self, journal)?;
        hash(exact_envelope_digest).map_err(|_| TransportError::WrongContext)?;
        let records = journal
            .acquire_preconstruction_records(
                &self.record.enrollment_ref,
                &self.record.manifest_ref,
                session,
            )
            .map_err(unavailable)?;
        records
            .require_native_origin(&self.source)
            .map_err(unavailable)?;
        let retained = load_original(journal, self, original_ref)?;
        require_own_context(self, &retained.record, own_policy, vault, &records)?;
        let terms = &retained.record.reservation_request.intent.terms;
        let context = MessageContext {
            network_profile_id: terms.network_profile_id.clone(),
            agreement_id: terms.agreement_id.clone(),
            proposal_id: terms.proposal_id.clone(),
            proposal_revision: terms.proposal_revision,
            sender_id: hex::encode(Sha256::digest(self.record.verifier_signing_public_key)),
            recipient_id: self.record.account_id.clone(),
            artifact_kind: ArtifactKind::NamedVerifierAssertion,
        };
        let history = {
            let c = journal
                .connection
                .lock()
                .map_err(|_| TransportError::Storage)?;
            let source = SignerNamedRecipientReceiptSource::from_authenticated_journal(
                &c,
                &journal.database_identity,
            )?;
            source.retained_for_envelope(&self.record.reference, &context, exact_envelope_digest)?
        };
        let current = || {
            records.check_current().map_err(unavailable)?;
            self.source.check_current().map_err(unavailable)
        };
        current()?;
        let Some(history) = history else {
            return Ok(None);
        };
        let assertion = NamedVerifierExpectedContext {
            original_artifact_digest: &retained.record.original_artifact_digest,
            transformation_commitment: &retained.record.transformation_digest,
            manifest_digest: &terms.manifest_digest,
            original_context_digest: &retained.original_context_digest,
            original_request_digest: &retained.record.original_request_digest,
            validity_not_before_ms: retained.record.validity_not_before_ms,
            validity_expires_ms: retained.record.validity_expires_ms,
            transaction_expiry_height: terms.transaction_expiry_height,
            own_account_id: &self.record.account_id,
        };
        let expected = NamedVerifierEnvelopeExpectation {
            context: &context,
            original_terms: terms,
            own_policy,
            selected_verifier: &self.record.verifier_signing_public_key,
            assertion: &assertion,
        };
        let binding = NamedVerifierRetainedPackageBinding {
            package_digest: &retained.record.assertion_package_digest,
            canonical_artifact_digest: &retained.record.canonical_artifact_digest,
            assertion_digest: &retained.record.named_assertion_digest,
            own_policy_digest: &retained.record.own_policy_digest,
        };
        let recipient = TransportSecret::from_bytes(self.record.transport_secret)?;
        let sender = TransportPublicKey::from_bytes(self.record.verifier_transport_public_key)?;
        let result = recover_named_verifier_assertion_bound(
            &history, &recipient, &sender, &expected, &binding, current,
        )?;
        // All original windows are unchanged. This capability explicitly labels
        // itself historical and cannot be converted into admission or key use.
        if result.is_new_delivery() || result.authorization_allowed() {
            return Err(TransportError::AuthorityUnavailable);
        }
        let _publication = self.source.publication_lease().map_err(unavailable)?;
        records.check_current().map_err(unavailable)?;
        self.source.check_current().map_err(unavailable)?;
        Ok(Some(result))
    }
}
