//! First-original intake: authenticated assertion, exact retained request and
//! once-sealed intent are committed together. No admission or key use occurs.
use super::super::super::{
    named_intent_transport as wire, named_recipient_records::NamedIntentOutboxRecordV1,
};
use super::*;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
pub(super) mod file_destination;
use file_destination::ExactFileDestination;
use wholepact_authority::offline::{OfflineEnrollmentPolicy, ReserveOfflineAuthorization};
use wholepact_transport::{
    DisclosurePreview, MessageOrder, NAMED_REVIEW_BINDING_FIELD_V1, OfflineIntentHandoffV1,
};

/// Untrusted local draft. Sequence must be zero; this owner predicts and reviews
/// the exact next retained sequence, then rejects if it changed before commit.
/// This is separate from the witness's admission reply template.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamedIntentExportTemplate {
    pub(crate) order: MessageOrder,
    pub(crate) purpose: String,
    pub(crate) persistence_warning: String,
}

/// Owned preparation data, including the independently derived wallet policy.
/// No field grants authority; preparation checks every relation against the
/// actual retained profile, native source, session, vault and journal.
pub(crate) struct NamedRecipientOriginalInputs {
    pub(crate) proposed: NamedRecipientOriginalRecordV1,
    pub(crate) own_policy: OwnEffectsPolicy,
    pub(crate) proposed_policy: OfflineEnrollmentPolicy,
    pub(crate) assertion_envelope: EncryptedEnvelope,
    pub(crate) outgoing: NamedIntentExportTemplate,
    pub(crate) now: Timestamp,
}

/// Owns genuine process-local source/journal association, but is not approved.
/// No raw constructor, Clone, Debug, Deserialize or authority conversion exists.
pub(crate) struct PreparedNamedRecipientOriginalImport {
    operation: Option<super::NamedRecipientOperation>,
    checkpoint_input: Option<super::born_checkpoint_input::PreparedBornCheckpointInputV1>,
    profile: LiveNamedRecipientProfile,
    original: NamedRecipientOriginalRecordV1,
    own_policy: OwnEffectsPolicy,
    proposed_policy: OfflineEnrollmentPolicy,
    assertion_envelope: EncryptedEnvelope,
    assertion_envelope_digest: String,
    prepared_wall_milliseconds: u64,
    original_window_deadline: Instant,
    outgoing: wire::PreparedExport,
    created: Instant,
    digest: String,
    display: String,
}

/// Exact durable ciphertext, still requiring a separate actual native file
/// export decision. Historical recovery can return this but no live admission.
pub(crate) struct RetainedNamedIntentExport {
    profile: LiveNamedRecipientProfile,
    original: NamedRecipientOriginalRecordV1,
    outbox: NamedIntentOutboxRecordV1,
    envelope: EncryptedEnvelope,
    digest: String,
    display: String,
}

impl LiveNamedRecipientProfile {
    pub(crate) fn enrollment_ref(&self) -> &str {
        &self.record.enrollment_ref
    }
    pub(crate) fn manifest_ref(&self) -> &str {
        &self.record.manifest_ref
    }
    pub(crate) fn prepare_original_import(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        inputs: NamedRecipientOriginalInputs,
    ) -> ImportResult<PreparedNamedRecipientOriginalImport> {
        inputs
            .proposed
            .require_legacy_origin()
            .map_err(|_| TransportError::AuthorityUnavailable)?;
        self.prepare_original_import_inner(journal, session, vault, inputs)
    }
    fn prepare_original_import_inner(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        inputs: NamedRecipientOriginalInputs,
    ) -> ImportResult<PreparedNamedRecipientOriginalImport> {
        let NamedRecipientOriginalInputs {
            mut proposed,
            own_policy,
            proposed_policy,
            assertion_envelope,
            mut outgoing,
            now,
        } = inputs;
        require_profile_owner(self, journal)?;
        // Capture the monotonic base first, so time spent sampling wall time or
        // preparing cannot extend any original validity window.
        let original_window_started = Instant::now();
        let prepared_wall_milliseconds = local_wall_milliseconds()?;
        let original_window_deadline = original_window_started
            .checked_add(Duration::from_millis(remaining_original_window_ms(
                prepared_wall_milliseconds,
                proposed.reservation_request.admission_expires_at_ms,
                proposed.validity_expires_ms,
                outgoing.order.expires_at.unix_seconds(),
            )?))
            .ok_or(TransportError::InvalidTime)?;
        if outgoing.order.sequence != 0
            || proposed.reservation_request.intent.terms != proposed.terms
            || proposed.profile_ref != self.record.reference
        {
            return Err(TransportError::WrongContext);
        }
        proposed
            .terms
            .validate()
            .map_err(|_| TransportError::WrongContext)?;
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
        let context = draft_intent_context(&proposed.terms, proposed.born_origin.is_some())?;
        let stream = wire::stream_digest(&context).map_err(codec_error)?;
        let profile_record = {
            let c = journal
                .connection
                .lock()
                .map_err(|_| TransportError::Storage)?;
            let record = exact_profile(&c, self, journal)?;
            require_new_authorization(&c, &proposed.terms.authorization_id)?;
            if let Some(origin) = &proposed.born_origin {
                origin
                    .require_actual_signer(&c, &record, records.enrollment())
                    .map_err(|_| TransportError::WrongContext)?;
            } else {
                require_legacy_new_original_account(&c, &record.account_id)?;
            }
            outgoing.order.sequence = next_outgoing_sequence(&c, &record.reference, &stream)?;
            record
        };
        let assertion_envelope_digest = envelope_commitment(assertion_envelope.as_bytes())?;
        // Neither caller-supplied native review nor its derived request/reference
        // hashes enter this normalization. All actual head/time/terms are included.
        let reviewed =
            original_review_digest(self, &proposed, &outgoing, &assertion_envelope_digest)?;
        proposed
            .reservation_request
            .intent
            .native_reservation_review_digest = reviewed.clone();
        if let Some(origin) = &mut proposed.born_origin {
            origin.request.reservation = proposed.reservation_request.clone();
        }
        proposed.reservation_request_digest = proposed
            .reservation_request
            .request_digest()
            .map_err(|_| TransportError::WrongContext)?;
        proposed.reference = proposed
            .reference_digest()
            .map_err(|_| TransportError::WrongContext)?;
        // Full policy/origin validation remains under the SAME actual lease.
        // Normalize the real local review first; no supplied digest is consent.
        require_proposed_policy(&profile_record, &proposed, &proposed_policy)?;
        require_same_intent_context(&context, &intent_context(&proposed)?)?;
        require_own_context(self, &proposed, &own_policy, vault, &records)?;
        let prepared = prepare_intent(self, &proposed, outgoing, &now)?;
        if prepared
            .retained_metadata()
            .map_err(codec_error)?
            .stream_digest
            != stream
        {
            return Err(TransportError::WrongContext);
        }
        let preview = public_preview(prepared.preview())?;
        let display = original_display(self, &proposed, &preview, &assertion_envelope_digest)?;
        records.check_current().map_err(unavailable)?;
        check_setup_current(&self.source, original_window_deadline).map_err(unavailable)?;
        Ok(PreparedNamedRecipientOriginalImport {
            operation: None,
            checkpoint_input: None,
            profile: LiveNamedRecipientProfile {
                record: profile_record,
                journal: self.journal.clone(),
                source: self.source.clone(),
            },
            original: proposed,
            own_policy,
            proposed_policy,
            assertion_envelope,
            assertion_envelope_digest,
            prepared_wall_milliseconds,
            original_window_deadline,
            outgoing: prepared,
            created: Instant::now(),
            digest: reviewed,
            display,
        })
    }

    /// Lookup uses the authorization ID known before commit. This never retries
    /// first-original creation, reconstructs a request, reallocates or reseals.
    pub(crate) fn recover_original_intent_export(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        authorization_id: &str,
    ) -> ImportResult<Option<RetainedNamedIntentExport>> {
        let result =
            self.recover_original_intent_export_inner(journal, session, vault, authorization_id)?;
        if result
            .as_ref()
            .is_some_and(|r| r.original.born_origin.is_some())
        {
            return Err(TransportError::AuthorityUnavailable);
        }
        Ok(result)
    }
    fn recover_original_intent_export_inner(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        authorization_id: &str,
    ) -> ImportResult<Option<RetainedNamedIntentExport>> {
        require_profile_owner(self, journal)?;
        id(authorization_id).map_err(|_| TransportError::WrongContext)?;
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
        let retained = {
            let c = journal
                .connection
                .lock()
                .map_err(|_| TransportError::Storage)?;
            let record = exact_profile(&c, self, journal)?;
            let original = read_original_by_authorization(&c, &record, authorization_id)?;
            match original {
                None => None,
                Some(original) => {
                    if let Some(origin) = &original.born_origin {
                        origin
                            .checkpoint_receipt
                            .require_retained(&c)
                            .map_err(unavailable)?;
                    }
                    let outbox = read_outbox(&c, &original, &record)?;
                    Some((record, original, outbox))
                }
            }
        };
        let Some((record, original, outbox)) = retained else {
            records.check_current().map_err(unavailable)?;
            self.source.check_current().map_err(unavailable)?;
            return Ok(None);
        };
        require_historical_context(self, &original, vault, &records)?;
        let result = retained_export(
            LiveNamedRecipientProfile {
                record,
                journal: self.journal.clone(),
                source: self.source.clone(),
            },
            original,
            outbox,
        )?;
        let _publication = self.source.publication_lease().map_err(unavailable)?;
        records.check_current().map_err(unavailable)?;
        self.source.check_current().map_err(unavailable)?;
        Ok(Some(result))
    }
}

impl PreparedNamedRecipientOriginalImport {
    #[cfg(all(test, feature = "synthetic-qualification"))]
    pub(in crate::consent_journal::named_recipient_setup) fn expire_fixture_review(&mut self) {
        self.created = Instant::now()
            .checked_sub(Duration::from_secs(121))
            .unwrap();
    }
    #[cfg(all(test, feature = "synthetic-qualification"))]
    pub(in crate::consent_journal::named_recipient_setup) fn expire_fixture_original_window(
        &mut self,
    ) {
        self.original_window_deadline = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap();
    }
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn display(&self) -> &str {
        &self.display
    }
    pub(crate) fn authorization_id(&self) -> &str {
        &self.original.terms.authorization_id
    }
    pub(crate) fn approve(
        self,
        decision: NativeDecision,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        now: &Timestamp,
    ) -> ImportResult<RetainedNamedIntentExport> {
        self.original
            .require_legacy_origin()
            .map_err(|_| TransportError::AuthorityUnavailable)?;
        self.approve_inner(decision, journal, session, vault, now)
    }
    fn approve_inner(
        self,
        decision: NativeDecision,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        now: &Timestamp,
    ) -> ImportResult<RetainedNamedIntentExport> {
        require_profile_owner(&self.profile, journal)?;
        if decision.binding() != &self.profile.source
            || decision.reviewed_digest() != self.digest
            || self
                .original
                .reservation_request
                .intent
                .native_reservation_review_digest
                != self.digest
            || envelope_commitment(self.assertion_envelope.as_bytes())?
                != self.assertion_envelope_digest
        {
            return Err(TransportError::WrongContext);
        }
        let expires = review_deadline(self.created, &decision)?.min(self.original_window_deadline);
        check_setup_current(&self.profile.source, expires).map_err(unavailable)?;
        let records = journal
            .acquire_preconstruction_records(
                &self.profile.record.enrollment_ref,
                &self.profile.record.manifest_ref,
                session,
            )
            .map_err(unavailable)?;
        records
            .require_native_origin(&self.profile.source)
            .map_err(unavailable)?;
        require_own_context(
            &self.profile,
            &self.original,
            &self.own_policy,
            vault,
            &records,
        )?;
        require_proposed_policy(&self.profile.record, &self.original, &self.proposed_policy)?;
        let (context_digest, _) = require_original_binding(&self.profile, &self.original)?;
        let terms = &self.original.reservation_request.intent.terms;
        let context = MessageContext {
            network_profile_id: terms.network_profile_id.clone(),
            agreement_id: terms.agreement_id.clone(),
            proposal_id: terms.proposal_id.clone(),
            proposal_revision: terms.proposal_revision,
            sender_id: hex::encode(Sha256::digest(
                self.profile.record.verifier_signing_public_key,
            )),
            recipient_id: self.profile.record.account_id.clone(),
            artifact_kind: ArtifactKind::NamedVerifierAssertion,
        };
        let assertion = NamedVerifierExpectedContext {
            original_artifact_digest: &self.original.original_artifact_digest,
            transformation_commitment: &self.original.transformation_digest,
            manifest_digest: &terms.manifest_digest,
            original_context_digest: &context_digest,
            original_request_digest: &self.original.original_request_digest,
            validity_not_before_ms: self.original.validity_not_before_ms,
            validity_expires_ms: self.original.validity_expires_ms,
            transaction_expiry_height: terms.transaction_expiry_height,
            own_account_id: &self.profile.record.account_id,
        };
        let expected = NamedVerifierEnvelopeExpectation {
            context: &context,
            original_terms: terms,
            own_policy: &self.own_policy,
            selected_verifier: &self.profile.record.verifier_signing_public_key,
            assertion: &assertion,
        };
        let exact = NamedVerifierRetainedPackageBinding {
            package_digest: &self.original.assertion_package_digest,
            canonical_artifact_digest: &self.original.canonical_artifact_digest,
            assertion_digest: &self.original.named_assertion_digest,
            own_policy_digest: &self.original.own_policy_digest,
        };
        let recipient = TransportSecret::from_bytes(self.profile.record.transport_secret)?;
        let sender =
            TransportPublicKey::from_bytes(self.profile.record.verifier_transport_public_key)?;
        let current = || {
            if let Some(operation) = &self.operation {
                operation.check()?;
            }
            records.check_current().map_err(unavailable)?;
            check_setup_current(&self.profile.source, expires).map_err(unavailable)
        };
        let mut ledger = FirstOriginalLedger {
            operation: self.operation.as_ref(),
            checkpoint_input: self.checkpoint_input.as_ref(),
            journal,
            profile: &self.profile,
            original: &self.original,
            proposed_policy: &self.proposed_policy,
            records: &records,
            expires,
            assertion_envelope_digest: &self.assertion_envelope_digest,
            minimum_wall_milliseconds: self.prepared_wall_milliseconds.max(
                u64::try_from(now.unix_seconds())
                    .ok()
                    .and_then(|seconds| seconds.checked_mul(1000))
                    .ok_or(TransportError::InvalidTime)?,
            ),
            outgoing: Some(self.outgoing),
            retained: None,
        };
        // This calls the ledger only after signature, exact package, full own
        // effects and every retained commitment pass. No placeholder row exists.
        let _verified = open_named_verifier_assertion_bound(
            &self.assertion_envelope,
            &recipient,
            &sender,
            &expected,
            &exact,
            now,
            &mut ledger,
            current,
        )?;
        let outbox = ledger
            .retained
            .take()
            .ok_or(TransportError::ImportCommittedButUnavailable)?;
        drop(ledger);
        // Any fallible output construction after commit has an exact historical
        // lookup target. Never turn such a failure into permission to reseal.
        let result = retained_export(self.profile, self.original, outbox)
            .map_err(|_| TransportError::ImportCommittedButUnavailable)?;
        let publication = result
            .profile
            .source
            .publication_lease()
            .map_err(|_| TransportError::ImportCommittedButUnavailable)?;
        records
            .check_current()
            .map_err(|_| TransportError::ImportCommittedButUnavailable)?;
        result
            .profile
            .source
            .check_current()
            .map_err(|_| TransportError::ImportCommittedButUnavailable)?;
        drop(publication);
        Ok(result)
    }
}

/// Exact resolved output destination is part of this separate native review.
/// No arbitrary destination can be supplied after the decision is consumed.
pub(crate) struct PreparedNamedIntentFileExport {
    operation: Option<super::NamedRecipientOperation>,
    retained: RetainedNamedIntentExport,
    destination: ExactFileDestination,
    handoff_bytes: Zeroizing<Vec<u8>>,
    created: Instant,
    digest: String,
    display: String,
}
impl RetainedNamedIntentExport {
    pub(crate) fn display(&self) -> &str {
        &self.display
    }
    pub(crate) fn authorization_id(&self) -> &str {
        &self.original.terms.authorization_id
    }
    pub(crate) fn original_ref(&self) -> &str {
        &self.original.reference
    }
    pub(crate) fn prepare_file_export(
        self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        destination: &Path,
    ) -> ImportResult<PreparedNamedIntentFileExport> {
        self.original
            .require_legacy_origin()
            .map_err(|_| TransportError::AuthorityUnavailable)?;
        self.prepare_file_export_inner(journal, session, vault, destination)
    }
    fn prepare_file_export_inner(
        self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        destination: &Path,
    ) -> ImportResult<PreparedNamedIntentFileExport> {
        self.require_exact_current(journal, session, vault)?;
        let destination = ExactFileDestination::prepare(destination)?;
        let handoff = born_intent_file::ExactIntentHandoff::from_original(
            &self.original,
            self.envelope.as_bytes(),
        )?;
        let handoff_digest = handoff.commitment()?;
        let handoff_bytes = Zeroizing::new(handoff.canonical_bytes()?);
        let request_display = handoff.request_display()?;
        let reply_display = handoff.reply_display()?;
        let reviewed = digest(
            "wholepact:native-named-intent-file-export:v1",
            &(
                &self.digest,
                destination.review_binding(),
                &handoff_digest,
                &self.outbox.envelope_digest,
                self.profile.source.entry_digest(),
            ),
        )
        .map_err(|_| TransportError::ResourceLimit)?;
        let display = format!(
            "{}\nExact new private destination: {}\nController handoff commitment: {handoff_digest}\nThis plaintext handoff discloses your full original own request, effect commitments and input identifiers to the chosen online controller, together with the original encrypted intent and admission reply template. It excludes the named assertion package and peer FVK. No witness enrollment or signing authority is created by this file.\nOriginal request: {request_display}\nOriginal reply template: {reply_display}\nThe retained directory identity is part of this review. The existing file will never be overwritten.",
            self.display,
            destination.display_path().display()
        );
        self.profile.source.check_current().map_err(unavailable)?;
        Ok(PreparedNamedIntentFileExport {
            operation: None,
            retained: self,
            destination,
            handoff_bytes,
            created: Instant::now(),
            digest: reviewed,
            display,
        })
    }
    fn require_exact_current(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
    ) -> ImportResult<()> {
        require_profile_owner(&self.profile, journal)?;
        let records = journal
            .acquire_preconstruction_records(
                &self.profile.record.enrollment_ref,
                &self.profile.record.manifest_ref,
                session,
            )
            .map_err(unavailable)?;
        self.require_exact_records(journal, vault, &records)?;
        records.check_current().map_err(unavailable)?;
        self.profile.source.check_current().map_err(unavailable)
    }
    fn require_exact_records(
        &self,
        journal: &SignerConsentJournal,
        vault: &AccountVault,
        records: &PreconstructionRecordLease<'_>,
    ) -> ImportResult<()> {
        records
            .require_journal(&self.profile.journal)
            .map_err(unavailable)?;
        records
            .require_native_origin(&self.profile.source)
            .map_err(unavailable)?;
        require_historical_context(&self.profile, &self.original, vault, records)?;
        let c = journal
            .connection
            .lock()
            .map_err(|_| TransportError::Storage)?;
        exact_profile(&c, &self.profile, journal)?;
        let original =
            read_original_by_authorization(&c, &self.profile.record, self.authorization_id())?
                .ok_or(TransportError::WrongContext)?;
        let outbox = read_outbox(&c, &original, &self.profile.record)?;
        if let Some(origin) = &original.born_origin {
            origin
                .require_retained_signer(&c, &self.profile.record, records.enrollment())
                .map_err(|_| TransportError::WrongContext)?;
        }
        if original != self.original
            || outbox != self.outbox
            || envelope_commitment(self.envelope.as_bytes())? != outbox.envelope_digest
        {
            return Err(TransportError::WrongContext);
        }
        Ok(())
    }
}
impl PreparedNamedIntentFileExport {
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn display(&self) -> &str {
        &self.display
    }
    /// Only the exact original controller handoff is written, to the destination previously
    /// bound into the genuine native decision, while currentness fences are held.
    pub(crate) fn write_new_file(
        self,
        decision: NativeDecision,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
    ) -> ImportResult<()> {
        if let Some(operation) = &self.operation {
            operation.check()?;
        }
        require_profile_owner(&self.retained.profile, journal)?;
        if decision.binding() != &self.retained.profile.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(TransportError::WrongContext);
        }
        let expires = review_deadline(self.created, &decision)?;
        let records = journal
            .acquire_preconstruction_records(
                &self.retained.profile.record.enrollment_ref,
                &self.retained.profile.record.manifest_ref,
                session,
            )
            .map_err(unavailable)?;
        self.retained
            .require_exact_records(journal, vault, &records)?;
        self.destination.check_directory()?;
        records.check_current().map_err(unavailable)?;
        check_setup_current(&self.retained.profile.source, expires).map_err(unavailable)?;
        // Allocate outside the publication fence. A delayed filesystem operation
        // cannot extend native consent; after creation every error is uncertain.
        if let Some(operation) = &self.operation {
            operation.check()?;
        }
        let mut file = self.destination.allocate()?;
        let result = (|| -> ImportResult<()> {
            self.destination.check_created(&file, 0)?;
            records.check_current().map_err(unavailable)?;
            check_setup_current(&self.retained.profile.source, expires).map_err(unavailable)?;
            // The fence covers only admitted handoff publication, not allocation.
            let _publication = self
                .retained
                .profile
                .source
                .publication_lease()
                .map_err(unavailable)?;
            self.destination.check_created(&file, 0)?;
            records.check_current().map_err(unavailable)?;
            check_setup_current(&self.retained.profile.source, expires).map_err(unavailable)?;
            // This is the first handoff write, immediately after the original
            // deadline/session/source checks. No renewal or fresh approval hash.
            if let Some(operation) = &self.operation {
                operation.check()?;
            }
            file.write_all(self.handoff_bytes.as_slice())
                .map_err(|_| TransportError::Storage)?;
            file.sync_all().map_err(|_| TransportError::Storage)?;
            self.destination.sync_parent()?;
            if let Some(operation) = &self.operation {
                operation.check()?;
            }
            self.destination
                .check_created(&file, self.handoff_bytes.len() as u64)?;
            records.check_current().map_err(unavailable)?;
            check_setup_current(&self.retained.profile.source, expires).map_err(unavailable)
        })();
        // Never unlink, overwrite, replace or reseal after a created/partial file.
        result.map_err(|_| TransportError::ImportCommittedButUnavailable)
    }
}

// Only this genuine native approval path creates this ledger. It is not exported
// and cannot receive raw receipt records in place of AuthenticatedReceipt.
struct FirstOriginalLedger<'a, 'lease> {
    operation: Option<&'a super::NamedRecipientOperation>,
    checkpoint_input: Option<&'a super::born_checkpoint_input::PreparedBornCheckpointInputV1>,
    journal: &'a SignerConsentJournal,
    profile: &'a LiveNamedRecipientProfile,
    original: &'a NamedRecipientOriginalRecordV1,
    proposed_policy: &'a OfflineEnrollmentPolicy,
    records: &'a PreconstructionRecordLease<'lease>,
    expires: Instant,
    assertion_envelope_digest: &'a str,
    minimum_wall_milliseconds: u64,
    outgoing: Option<wire::PreparedExport>,
    retained: Option<NamedIntentOutboxRecordV1>,
}
impl FirstOriginalLedger<'_, '_> {
    fn current(&self) -> ImportResult<()> {
        if let Some(operation) = self.operation {
            operation.check()?;
        }
        self.records.check_current().map_err(unavailable)?;
        check_setup_current(&self.profile.source, self.expires).map_err(unavailable)
    }
}
impl ReplayLedger for FirstOriginalLedger<'_, '_> {
    fn accept_authenticated(
        &mut self,
        receipt: &AuthenticatedReceipt,
        encrypted: &[u8],
    ) -> ImportResult<()> {
        self.current()?;
        if envelope_commitment(encrypted)? != self.assertion_envelope_digest
            || receipt.envelope_digest() != self.assertion_envelope_digest
            || self.retained.is_some()
        {
            return Err(TransportError::WrongContext);
        }
        let prepared = self
            .outgoing
            .take()
            .ok_or(TransportError::AuthorityUnavailable)?;
        let metadata = prepared.retained_metadata().map_err(codec_error)?;
        let preview_json =
            serde_json::to_string(prepared.preview()).map_err(|_| TransportError::Malformed)?;
        let preview_digest = prepared.preview().digest().map_err(codec_error)?;
        let order = prepared.preview().order.clone();
        let sequence = order.sequence;
        let mut c = self
            .journal
            .connection
            .lock()
            .map_err(|_| TransportError::Storage)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| TransportError::Storage)?;
        exact_profile(&tx, self.profile, self.journal)?;
        require_new_authorization(&tx, &self.original.terms.authorization_id)?;
        require_proposed_policy(&self.profile.record, self.original, self.proposed_policy)?;
        if let Some(origin) = &self.original.born_origin {
            origin
                .require_actual_signer(&tx, &self.profile.record, self.records.enrollment())
                .map_err(|_| TransportError::WrongContext)?;
        } else {
            require_legacy_new_original_account(&tx, &self.profile.record.account_id)?;
        }
        if next_outgoing_sequence(&tx, &self.profile.record.reference, &metadata.stream_digest)?
            != sequence
        {
            return Err(TransportError::OutOfOrder);
        }
        require_outbox_capacity(
            &tx,
            &self.profile.record.reference,
            &metadata.stream_digest,
            0,
        )?;
        // Replay/sequence/slot collisions fail before consuming randomness.
        // This receipt is uncommitted until original and outbound bytes join it.
        insert_authenticated(&tx, &self.profile.record.reference, receipt, encrypted)?;
        match (&self.original.born_origin, self.checkpoint_input) {
            (Some(_), Some(checkpoint)) => {
                checkpoint.commit_into(&tx, self.profile, self.original, self.records)?
            }
            (None, None) => {}
            _ => return Err(TransportError::AuthorityUnavailable),
        }
        let sender = wire::TransportSecret::from_bytes(self.profile.record.transport_secret)
            .map_err(codec_error)?;
        // SQL-lock acquisition, receipt collisions and metadata work can block.
        // Admit sealing only after fresh checks under a short publication fence.
        let envelope = {
            let _seal_publication = self
                .profile
                .source
                .publication_lease()
                .map_err(unavailable)?;
            self.current()?;
            let seal_now =
                local_time_for_original(self.original, &order, self.minimum_wall_milliseconds)?;
            if self.original.born_origin.is_some() {
                wire::seal_born_original_intent(prepared, &sender, &preview_digest, &seal_now)
            } else {
                wire::seal_original_intent(prepared, &sender, &preview_digest, &seal_now)
            }
            .map_err(codec_error)?
        };
        // The immutable original must fit the actual bounded witness route.
        // The inert handoff validator uses its maintained wire-size preflight;
        // failure here rolls back the uncommitted inbound receipt as well.
        let candidate_handoff = born_intent_file::ExactIntentHandoff::from_original(
            self.original,
            envelope.as_bytes(),
        )?;
        let _bounded_handoff = Zeroizing::new(candidate_handoff.canonical_bytes()?);
        require_outbox_capacity(
            &tx,
            &self.profile.record.reference,
            &metadata.stream_digest,
            envelope.as_bytes().len(),
        )?;
        let outbox = NamedIntentOutboxRecordV1 {
            authorization_id: self.original.terms.authorization_id.clone(),
            original_ref: self.original.reference.clone(),
            profile_ref: self.profile.record.reference.clone(),
            stream: metadata.stream_digest,
            sequence,
            message_id: metadata.message_id_digest,
            content_hash: metadata.content_digest,
            payload_digest: metadata.payload_digest,
            envelope_digest: envelope_commitment(envelope.as_bytes())?,
            preview_json,
            envelope_hex: hex::encode(envelope.as_bytes()),
        };
        outbox
            .validate(self.original, &self.profile.record)
            .map_err(|_| TransportError::WrongContext)?;
        let payload = encode(self.original).map_err(|_| TransportError::ResourceLimit)?;
        tx.execute("INSERT INTO signer_named_recipient_originals(reference,profile_ref,authorization_id,payload) VALUES(?1,?2,?3,?4)",
            params![self.original.reference,self.original.profile_ref,self.original.terms.authorization_id,payload.as_str()])
            .map_err(|_| TransportError::Storage)?;
        tx.execute("INSERT INTO signer_named_intent_outbox(authorization_id,original_ref,profile_ref,stream,sequence,message_id,content_hash,payload_digest,envelope_digest,preview_json,envelope_hex) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![outbox.authorization_id,outbox.original_ref,outbox.profile_ref,outbox.stream,outbox.sequence as i64,outbox.message_id,outbox.content_hash,outbox.payload_digest,outbox.envelope_digest,outbox.preview_json,outbox.envelope_hex])
            .map_err(|_| TransportError::Storage)?;
        storage::bounded(&tx, self.journal.capacity_limits())
            .map_err(|_| TransportError::ResourceLimit)?;
        super::super::super::named_recipient_inventory::read_all(
            &tx,
            &self.profile.record.account_id,
        )
        .map_err(|_| TransportError::WrongContext)?;
        self.records.check_current().map_err(unavailable)?;
        let _publication = self
            .profile
            .source
            .publication_lease()
            .map_err(unavailable)?;
        self.current()?;
        local_time_for_original(self.original, &order, self.minimum_wall_milliseconds)?;
        tx.commit()
            .map_err(|_| TransportError::ImportCommittedButUnavailable)?;
        self.current()
            .map_err(|_| TransportError::ImportCommittedButUnavailable)?;
        local_time_for_original(self.original, &order, self.minimum_wall_milliseconds)
            .map_err(|_| TransportError::ImportCommittedButUnavailable)?;
        self.retained = Some(outbox);
        Ok(())
    }
}

// Retain a fixed monotonic ceiling in addition to current wall-time checks.
// Rolling wall time back above its original floor cannot extend this duration.
fn remaining_original_window_ms(
    captured_wall_ms: u64,
    request_end_ms: u64,
    assertion_end_ms: u64,
    outgoing_end_seconds: i64,
) -> ImportResult<u64> {
    let outgoing_end_ms = u64::try_from(outgoing_end_seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .ok_or(TransportError::InvalidTime)?;
    request_end_ms
        .min(assertion_end_ms)
        .min(outgoing_end_ms)
        .checked_sub(captured_wall_ms)
        .filter(|remaining| *remaining > 0)
        .ok_or(TransportError::InvalidTime)
}

fn local_wall_milliseconds() -> ImportResult<u64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| TransportError::InvalidTime)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| TransportError::InvalidTime)
}
fn local_time_for_original(
    original: &NamedRecipientOriginalRecordV1,
    order: &wire::MessageOrder,
    minimum_wall_milliseconds: u64,
) -> ImportResult<wire::Timestamp> {
    let milliseconds = local_wall_milliseconds()?;
    let now = i64::try_from(milliseconds / 1000).map_err(|_| TransportError::InvalidTime)?;
    require_local_window(
        now,
        minimum_wall_milliseconds,
        milliseconds,
        LocalValidityBounds {
            request_start: original.reservation_request.requested_at_ms,
            request_end: original.reservation_request.admission_expires_at_ms,
            assertion_start: original.validity_not_before_ms,
            assertion_end: original.validity_expires_ms,
            outgoing_start: order.issued_at.unix_seconds(),
            outgoing_end: order.expires_at.unix_seconds(),
        },
    )?;
    wire::Timestamp::from_unix_seconds(now).map_err(codec_error)
}
// Clock labels are local expiry guards only, never authenticated current chain
// or witness authority. Neither original wall windows nor monotonic consent renew.
struct LocalValidityBounds {
    request_start: u64,
    request_end: u64,
    assertion_start: u64,
    assertion_end: u64,
    outgoing_start: i64,
    outgoing_end: i64,
}
fn require_local_window(
    now: i64,
    minimum: u64,
    milliseconds: u64,
    bounds: LocalValidityBounds,
) -> ImportResult<()> {
    if milliseconds < minimum
        || milliseconds < bounds.request_start
        || milliseconds >= bounds.request_end
        || milliseconds < bounds.assertion_start
        || milliseconds >= bounds.assertion_end
        || now < bounds.outgoing_start
        || now >= bounds.outgoing_end
    {
        return Err(TransportError::InvalidTime);
    }
    Ok(())
}

fn require_historical_context(
    profile: &LiveNamedRecipientProfile,
    original: &NamedRecipientOriginalRecordV1,
    vault: &AccountVault,
    records: &PreconstructionRecordLease<'_>,
) -> ImportResult<()> {
    records
        .require_journal(&profile.journal)
        .map_err(unavailable)?;
    records
        .require_native_origin(&profile.source)
        .map_err(unavailable)?;
    require_original_binding(profile, original)?;
    let fvk = vault.account().fvk().map_err(unavailable)?;
    if vault.account().recovery_required()
        || vault.account_id().map_err(unavailable)? != profile.record.account_id
        || hex::encode(Sha256::digest(fvk.to_bytes())) != profile.record.full_viewing_key_digest
        || records.enrollment().reference() != profile.record.enrollment_ref
        || records.enrollment().account_id() != profile.record.account_id
        || records.enrollment().account_fvk_digest() != profile.record.full_viewing_key_digest
        || records.manifest().reference() != profile.record.manifest_ref
        || records.manifest().enrollment_ref() != profile.record.enrollment_ref
        || records.manifest().manifest_digest() != original.terms.manifest_digest
        || records.manifest().proposal_digest() != original.terms.proposal_digest
    {
        return Err(TransportError::WrongContext);
    }
    records.check_current().map_err(unavailable)?;
    profile.source.check_current().map_err(unavailable)
}

fn exact_profile(
    c: &rusqlite::Connection,
    profile: &LiveNamedRecipientProfile,
    journal: &SignerConsentJournal,
) -> ImportResult<NamedRecipientProfileRecordV1> {
    storage::bounded(c, journal.capacity_limits()).map_err(|_| TransportError::ResourceLimit)?;
    super::super::super::named_recipient_inventory::read_all(c, &profile.record.account_id)
        .map_err(|_| TransportError::WrongContext)?;
    let raw: Option<Option<String>> = c.query_row(
        "SELECT CASE WHEN length(CAST(payload AS BLOB))<=?2 THEN payload ELSE NULL END FROM signer_named_recipient_profiles WHERE reference=?1",
        params![profile.record.reference,MAX_RECORD_BYTES as i64], |r| r.get(0),
    ).optional().map_err(|_| TransportError::Storage)?;
    let raw = raw
        .ok_or(TransportError::WrongContext)?
        .ok_or(TransportError::ResourceLimit)?;
    let record: NamedRecipientProfileRecordV1 =
        decode(raw).map_err(|_| TransportError::WrongContext)?;
    record
        .validate()
        .map_err(|_| TransportError::WrongContext)?;
    if record != profile.record {
        return Err(TransportError::WrongContext);
    }
    Ok(record)
}

fn require_new_authorization(c: &rusqlite::Connection, authorization_id: &str) -> ImportResult<()> {
    id(authorization_id).map_err(|_| TransportError::WrongContext)?;
    // Existing generic/legacy histories cannot become a new named authorization.
    // No deletion, terminal outcome or expired clock makes an ID reusable.
    let exists: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM signer_named_recipient_originals WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_named_intent_outbox WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_original_consents WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_offline_original_consents WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_offline_intents WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_offline_local_admissions WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_offline_review_inputs WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_remote_exposures WHERE authorization_id=?1)",
        [authorization_id], |r| r.get(0),
    ).map_err(|_| TransportError::Storage)?;
    if exists {
        Err(TransportError::Replay)
    } else {
        Ok(())
    }
}

fn next_outgoing_sequence(
    c: &rusqlite::Connection,
    profile: &str,
    stream: &str,
) -> ImportResult<u64> {
    let last: Option<i64> = c.query_row(
        "SELECT max(sequence) FROM signer_named_intent_outbox WHERE profile_ref=?1 AND stream=?2",
        params![profile,stream], |r| r.get(0),
    ).map_err(|_| TransportError::Storage)?;
    let next = last
        .unwrap_or(0)
        .checked_add(1)
        .filter(|n| *n > 0)
        .ok_or(TransportError::ResourceLimit)?;
    u64::try_from(next).map_err(|_| TransportError::ResourceLimit)
}

fn require_outbox_capacity(
    c: &rusqlite::Connection,
    profile: &str,
    stream: &str,
    incoming: usize,
) -> ImportResult<()> {
    let (count,bytes): (i64,i64) = c.query_row(
        "SELECT count(*),coalesce(sum(length(envelope_hex)/2),0) FROM signer_named_intent_outbox", [], |r| Ok((r.get(0)?,r.get(1)?)),
    ).map_err(|_| TransportError::Storage)?;
    let streams: i64 = c.query_row(
        "SELECT count(*) FROM (SELECT profile_ref,stream FROM signer_named_intent_outbox GROUP BY profile_ref,stream)", [], |r| r.get(0),
    ).map_err(|_| TransportError::Storage)?;
    let existing: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM signer_named_intent_outbox WHERE profile_ref=?1 AND stream=?2)", params![profile,stream], |r| r.get(0),
    ).map_err(|_| TransportError::Storage)?;
    check_capacity(count, streams, bytes, !existing, incoming)
}

/// Pure conjunction only. This policy is untrusted request data. Neither a DTO
/// nor these checks assert witness enrollment/current authority or grant a permit.
fn require_proposed_policy(
    profile: &NamedRecipientProfileRecordV1,
    original: &NamedRecipientOriginalRecordV1,
    policy: &OfflineEnrollmentPolicy,
) -> ImportResult<()> {
    policy
        .validate()
        .map_err(|_| TransportError::WrongContext)?;
    if let Some(origin) = &original.born_origin {
        if policy != &origin.enrollment.enrollment.policy {
            return Err(TransportError::WrongContext);
        }
        origin
            .validate_structure(profile, original)
            .map_err(|_| TransportError::WrongContext)?;
    }
    let request = &original.reservation_request;
    let terms = &request.intent.terms;
    let lifetime = request
        .admission_expires_at_ms
        .checked_sub(request.requested_at_ms)
        .filter(|n| *n > 0)
        .ok_or(TransportError::InvalidTime)?;
    let fingerprint = super::super::super::named_recipient_records::transport_fingerprint;
    if policy
        .policy_digest()
        .map_err(|_| TransportError::WrongContext)?
        != terms.offline_policy_digest
        || policy.account_id != profile.account_id
        || policy.account_id != terms.account_id
        || policy.network_profile_id != terms.network_profile_id
        || policy.enrollment_ref != profile.witness_enrollment_ref()
        || policy.enrollment_ref != terms.enrollment_ref
        || policy.witness_transport_key_digest != fingerprint(&profile.witness_transport_public_key)
        || policy.witness_certificate_digest != profile.witness_certificate_digest
        || policy.offline_signer_key_digest != fingerprint(&profile.transport_public_key)
        || policy.offline_signer_key_digest != terms.offline_signer_key_digest
        || policy.return_recipient_key_digest != fingerprint(&profile.return_transport_public_key)
        || policy.return_recipient_key_digest != terms.return_recipient_key_digest
        || policy.source_identity_digest != terms.snapshot.source_identity_digest
        || policy.source_policy_digest != terms.snapshot.source_policy_digest
        || policy.semantics != terms.semantics
        || request.requested_at_ms < policy.valid_from_ms
        || request.admission_expires_at_ms > policy.expires_at_ms
        || lifetime > policy.maximum_admission_lifetime_ms
    {
        return Err(TransportError::WrongContext);
    }
    Ok(())
}

// An explicit projection prevents a cycle through the review digest and its
// derived request/reference hashes. No expected head, writer epoch or time is
// replaced. The pre-package signed original_request_digest is separately bound.
#[derive(Serialize)]
struct NormalizedRequest<'a> {
    schema_version: u16,
    operation_id: &'a str,
    writer_epoch: u64,
    expected_head: &'a wholepact_authority::AuthorityHead,
    intent_schema_version: u16,
    intent_id: &'a str,
    terms: &'a wholepact_authority::offline::OfflineAuthorizationTerms,
    requested_at_ms: u64,
    admission_expires_at_ms: u64,
}
fn normalized_request(request: &ReserveOfflineAuthorization) -> NormalizedRequest<'_> {
    NormalizedRequest {
        schema_version: request.schema_version,
        operation_id: &request.operation_id,
        writer_epoch: request.writer_epoch,
        expected_head: &request.expected_head,
        intent_schema_version: request.intent.schema_version,
        intent_id: &request.intent.intent_id,
        terms: &request.intent.terms,
        requested_at_ms: request.requested_at_ms,
        admission_expires_at_ms: request.admission_expires_at_ms,
    }
}
fn original_review_digest(
    profile: &LiveNamedRecipientProfile,
    proposed: &NamedRecipientOriginalRecordV1,
    outgoing: &NamedIntentExportTemplate,
    assertion_envelope_digest: &str,
) -> ImportResult<String> {
    let legacy_review = digest(
        "wholepact:native-named-first-original-review:v1",
        &(
            &profile.record.reference,
            profile.source.entry_digest(),
            normalized_request(&proposed.reservation_request),
            (
                &proposed.schema_version,
                &proposed.profile_ref,
                &proposed.terms,
                &proposed.original_artifact_digest,
                &proposed.canonical_artifact_digest,
                &proposed.transformation_digest,
                &proposed.named_assertion_digest,
                &proposed.assertion_package_digest,
                &proposed.original_request_digest,
                proposed.validity_not_before_ms,
                proposed.validity_expires_ms,
            ),
            (
                &proposed.own_policy_digest,
                &proposed.own_expectations,
                &proposed.admission_export_template,
            ),
            (
                &outgoing.order,
                &outgoing.purpose,
                &outgoing.persistence_warning,
            ),
            (
                profile.record.transport_public_key,
                profile.record.witness_transport_public_key,
                &profile.record.witness_certificate_digest,
                profile.record.verifier_signing_public_key,
                profile.record.verifier_transport_public_key,
                profile.record.return_transport_public_key,
            ),
            assertion_envelope_digest,
        ),
    )
    .map_err(|_| TransportError::ResourceLimit)?;
    match &proposed.born_origin {
        None => Ok(legacy_review),
        Some(origin) => digest(
            "wholepact:native-born-named-first-original-review:v1",
            &(
                legacy_review,
                origin
                    .parent_binding_digest()
                    .map_err(|_| TransportError::WrongContext)?,
            ),
        )
        .map_err(|_| TransportError::ResourceLimit),
    }
}

fn intent_context(original: &NamedRecipientOriginalRecordV1) -> ImportResult<wire::MessageContext> {
    if let Some(origin) = &original.born_origin {
        let context = wholepact_transport::born_offline_intent_context_v1(&origin.request)?;
        return serde_json::from_slice(
            &serde_json::to_vec(&context).map_err(|_| TransportError::Malformed)?,
        )
        .map_err(|_| TransportError::Malformed);
    }
    let terms = &original.reservation_request.intent.terms;
    Ok(wire::MessageContext {
        network_profile_id: terms.network_profile_id.clone(),
        agreement_id: terms.agreement_id.clone(),
        proposal_id: terms.proposal_id.clone(),
        proposal_revision: terms.proposal_revision,
        sender_id: format!("offline-intent:{}", terms.offline_signer_key_digest),
        recipient_id: format!("offline-intent:{}", terms.offline_policy_digest),
        artifact_kind: wire::ArtifactKind::OfflineReservationIntent,
    })
}
fn prepare_intent(
    profile: &LiveNamedRecipientProfile,
    original: &NamedRecipientOriginalRecordV1,
    outgoing: NamedIntentExportTemplate,
    now: &Timestamp,
) -> ImportResult<wire::PreparedExport> {
    let (_, header) = require_original_binding(profile, original)?;
    let request = &original.reservation_request;
    let milliseconds = |n: i64| {
        u64::try_from(n)
            .ok()
            .and_then(|n| n.checked_mul(1000))
            .ok_or(TransportError::InvalidTime)
    };
    if milliseconds(outgoing.order.issued_at.unix_seconds())? < request.requested_at_ms
        || milliseconds(outgoing.order.expires_at.unix_seconds())? > request.admission_expires_at_ms
    {
        return Err(TransportError::InvalidTime);
    }
    let order: wire::MessageOrder = serde_json::from_slice(
        &serde_json::to_vec(&outgoing.order).map_err(|_| TransportError::Malformed)?,
    )
    .map_err(|_| TransportError::Malformed)?;
    wire::prepare_export(
        wire::ExportRequest {
            context: intent_context(original)?,
            order,
            purpose: outgoing.purpose,
            persistence_warning: outgoing.persistence_warning,
        },
        if let Some(origin) = &original.born_origin {
            wholepact_transport::born_offline_intent_fields_v1(&origin.request, &header)?
                .iter()
                .map(|field| {
                    wire::DisclosureField::new(field.name(), field.bytes().to_vec())
                        .map_err(codec_error)
                })
                .collect::<ImportResult<Vec<_>>>()?
        } else {
            vec![
                wire::DisclosureField::new(
                    "offline-reservation-intent-v1",
                    serde_json::to_vec(&request.intent).map_err(|_| TransportError::Malformed)?,
                )
                .map_err(codec_error)?,
                wire::DisclosureField::new(
                    NAMED_REVIEW_BINDING_FIELD_V1,
                    header.canonical_bytes()?,
                )
                .map_err(codec_error)?,
            ]
        },
        &wire::TransportPublicKey::from_bytes(profile.record.transport_public_key)
            .map_err(codec_error)?,
        &wire::TransportPublicKey::from_bytes(profile.record.witness_transport_public_key)
            .map_err(codec_error)?,
        &wire::Timestamp::from_unix_seconds(now.unix_seconds()).map_err(codec_error)?,
    )
    .map_err(codec_error)
}
fn public_preview(preview: &wire::DisclosurePreview) -> ImportResult<DisclosurePreview> {
    serde_json::from_slice(&serde_json::to_vec(preview).map_err(|_| TransportError::Malformed)?)
        .map_err(|_| TransportError::Malformed)
}
fn original_display(
    profile: &LiveNamedRecipientProfile,
    original: &NamedRecipientOriginalRecordV1,
    preview: &DisclosurePreview,
    assertion_envelope_digest: &str,
) -> ImportResult<String> {
    let request_json = serde_json::to_string_pretty(&original.reservation_request)
        .map_err(|_| TransportError::Malformed)?;
    let own_json = serde_json::to_string_pretty(&original.own_expectations)
        .map_err(|_| TransportError::Malformed)?;
    let reply_json = serde_json::to_string_pretty(&original.admission_export_template)
        .map_err(|_| TransportError::Malformed)?;
    let summary = format!(
        "RETAIN ORIGINAL NAMED-VERIFIER REQUEST\nAccount: {}\nProfile: {}\nAuthorization: {}\nExact encrypted assertion: {}\nAssertion package: {}\nOwn reservation: {} zatoshis\nOwn fee: {} zatoshis\nRequest: {}\nUntrusted proposed enrollment policy: {}\nSelected witness: {}\nWitness certificate: {}\nOutbound message: {} sequence {}\nOutbound validity: {} to {}\nPurpose: {}\nPersistence: {}\nThis authenticates named evidence and retains one exact request. Only the configured witness may verify enrolled policy and decide reservation. It does not admit funds, authorize signing, establish current chain facts, or enable independent verification. File export needs a separate native review.",
        profile.record.account_id,
        profile.record.reference,
        original.terms.authorization_id,
        assertion_envelope_digest,
        original.assertion_package_digest,
        original.terms.maximum_debit_zatoshis,
        original.terms.fee_share_zatoshis,
        original.reservation_request_digest,
        original.terms.offline_policy_digest,
        preview.recipient_key_fingerprint,
        profile.record.witness_certificate_digest,
        preview.order.message_id,
        preview.order.sequence,
        preview.order.issued_at.as_str(),
        preview.order.expires_at.as_str(),
        preview.purpose,
        preview.persistence_warning
    );
    let born_display = proposed_origin_display(original)?;
    Ok(format!(
        "{summary}{born_display}\nSelected verifier signing key: {}\nSelected verifier transport key: {}\nExact request: {request_json}\nExact independently checked own effects: {own_json}\nOriginal admission reply template: {reply_json}",
        hex::encode(profile.record.verifier_signing_public_key),
        hex::encode(profile.record.verifier_transport_public_key)
    ))
}
fn review_deadline(created: Instant, decision: &NativeDecision) -> ImportResult<Instant> {
    Ok(created
        .checked_add(Duration::from_secs(120))
        .ok_or(TransportError::InvalidTime)?
        .min(
            decision
                .consumed_at()
                .checked_add(Duration::from_secs(120))
                .ok_or(TransportError::InvalidTime)?,
        ))
}

// Only new legacy originals are fenced. Existing historical rows and exact
// recovery remain readable; an absent DTO origin cannot downgrade actual birth.
fn require_legacy_new_original_account(
    c: &rusqlite::Connection,
    account: &str,
) -> ImportResult<()> {
    let actual =
        super::super::super::account_use_storage::inspect(c, account).map_err(unavailable)?;
    if actual.genesis().is_some() || actual.exclusion().is_some() {
        return Err(TransportError::AuthorityUnavailable);
    }
    Ok(())
}

fn read_original_by_authorization(
    c: &rusqlite::Connection,
    profile: &NamedRecipientProfileRecordV1,
    authorization_id: &str,
) -> ImportResult<Option<NamedRecipientOriginalRecordV1>> {
    let raw: Option<Option<String>> = c.query_row(
        "SELECT CASE WHEN length(CAST(payload AS BLOB))<=?2 THEN payload ELSE NULL END FROM signer_named_recipient_originals WHERE authorization_id=?1",
        params![authorization_id,MAX_RECORD_BYTES as i64], |r| r.get(0),
    ).optional().map_err(|_| TransportError::Storage)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let original: NamedRecipientOriginalRecordV1 =
        decode(raw.ok_or(TransportError::ResourceLimit)?)
            .map_err(|_| TransportError::WrongContext)?;
    original
        .validate(profile)
        .map_err(|_| TransportError::WrongContext)?;
    if original.terms.authorization_id != authorization_id
        || original.profile_ref != profile.reference
    {
        return Err(TransportError::WrongContext);
    }
    Ok(Some(original))
}
fn read_outbox(
    c: &rusqlite::Connection,
    original: &NamedRecipientOriginalRecordV1,
    profile: &NamedRecipientProfileRecordV1,
) -> ImportResult<NamedIntentOutboxRecordV1> {
    let row: Option<NamedIntentOutboxRecordV1> = c.query_row(
        "SELECT substr(authorization_id,1,129),substr(original_ref,1,65),substr(profile_ref,1,65),substr(stream,1,65),sequence,substr(message_id,1,65),substr(content_hash,1,65),substr(payload_digest,1,65),substr(envelope_digest,1,65),CASE WHEN length(CAST(preview_json AS BLOB))<=?2 THEN preview_json ELSE NULL END,CASE WHEN length(CAST(envelope_hex AS BLOB))<=?3 THEN envelope_hex ELSE NULL END FROM signer_named_intent_outbox WHERE authorization_id=?1",
        params![original.terms.authorization_id,MAX_RECORD_BYTES as i64,(2*MAX_FILE_BYTES) as i64],
        |r| Ok(NamedIntentOutboxRecordV1 {
            authorization_id:r.get(0)?, original_ref:r.get(1)?, profile_ref:r.get(2)?, stream:r.get(3)?,
            sequence:r.get(4)?, message_id:r.get(5)?, content_hash:r.get(6)?, payload_digest:r.get(7)?,
            envelope_digest:r.get(8)?, preview_json:r.get(9)?, envelope_hex:r.get(10)?,
        }),
    ).optional().map_err(|_| TransportError::Storage)?;
    let row = row.ok_or(TransportError::WrongContext)?;
    row.validate(original, profile)
        .map_err(|_| TransportError::WrongContext)?;
    Ok(row)
}
fn retained_export(
    profile: LiveNamedRecipientProfile,
    original: NamedRecipientOriginalRecordV1,
    outbox: NamedIntentOutboxRecordV1,
) -> ImportResult<RetainedNamedIntentExport> {
    outbox
        .validate(&original, &profile.record)
        .map_err(|_| TransportError::WrongContext)?;
    let envelope = EncryptedEnvelope::from_bytes(
        hex::decode(&outbox.envelope_hex).map_err(|_| TransportError::Malformed)?,
    )?;
    let reviewed = digest(
        "wholepact:native-retained-named-intent:v1",
        &(
            &profile.record.reference,
            &original.reference,
            &original.reservation_request_digest,
            &original.admission_export_template,
            (
                &outbox.authorization_id,
                &outbox.original_ref,
                &outbox.profile_ref,
                &outbox.stream,
                outbox.sequence,
                &outbox.message_id,
                &outbox.content_hash,
                &outbox.payload_digest,
                &outbox.envelope_digest,
                &outbox.preview_json,
            ),
            profile.source.entry_digest(),
        ),
    )
    .map_err(|_| TransportError::ResourceLimit)?;
    let display = format!(
        "EXPORT EXACT HISTORICAL ORIGINAL NAMED INTENT\nAuthorization: {}\nOriginal: {}\nRequest: {}\nEncrypted file: {}\nExact retained disclosure: {}\nThis exports only the original retained ciphertext. The original expiry is unchanged. It does not retry reservation, renew deadlines, prove delivery, authorize key use or grant witness authority.",
        original.terms.authorization_id,
        original.reference,
        original.reservation_request_digest,
        outbox.envelope_digest,
        outbox.preview_json
    );
    Ok(RetainedNamedIntentExport {
        profile,
        original,
        outbox,
        envelope,
        digest: reviewed,
        display,
    })
}

// Nominal private codec errors never become trust flags or are ignored. Map each
// maintained variant explicitly; a future variant fails compilation for review.
fn codec_error(error: wire::TransportError) -> TransportError {
    use wire::TransportError as E;
    match error {
        E::UnsupportedVersion => TransportError::UnsupportedVersion,
        E::Malformed => TransportError::Malformed,
        E::ResourceLimit => TransportError::ResourceLimit,
        E::Authentication => TransportError::Authentication,
        E::WrongRecipient => TransportError::WrongRecipient,
        E::WrongNetwork => TransportError::WrongNetwork,
        E::WrongContext => TransportError::WrongContext,
        E::InvalidTime => TransportError::InvalidTime,
        E::DisclosureDenied => TransportError::DisclosureDenied,
        E::Replay => TransportError::Replay,
        E::Equivocation => TransportError::Equivocation,
        E::OutOfOrder => TransportError::OutOfOrder,
        E::Storage => TransportError::Storage,
        E::ImportCommittedButUnavailable => TransportError::ImportCommittedButUnavailable,
        E::Randomness => TransportError::Randomness,
        E::WeakPassword => TransportError::WeakPassword,
        E::AuthorityUnavailable => TransportError::AuthorityUnavailable,
        E::DomainConflict => TransportError::DomainConflict,
    }
}

#[cfg(test)]
#[path = "original_import/local_window_tests.rs"]
mod local_window_tests;

fn proposed_origin_display(original: &NamedRecipientOriginalRecordV1) -> ImportResult<String> {
    match &original.born_origin {
        None => Ok(String::new()),
        Some(origin) => Ok(format!(
            "\nPURPOSE-DISTINCT BORN ORIGINAL. Legacy submission/signing is forbidden. Exact authenticated parent evidence (historical only): {}",
            serde_json::to_string_pretty(origin).map_err(|_| TransportError::Malformed)?
        )),
    }
}
mod born;
mod born_intent_file;
pub(crate) use born::{
    BornNamedRecipientOriginalInputs, PreparedBornNamedIntentFileExport,
    PreparedBornNamedRecipientOriginalImport, RetainedBornNamedIntentExport,
};
pub(crate) use born_intent_file::BornIntentHandoffV1;
mod born_courier;
pub(crate) use born_courier::{
    BornCourierActionV1, PreparedBornDeliveryFileV1, PreparedBornIntentCourierV1,
    RetainedBornCourierDeliveryV1,
};

// Read-only preallocation routing from validated terms. This is never sealed or
// retained; full maintained request context equality is mandatory after review
// normalization. In particular no fake native-review hash is needed here.
fn draft_intent_context(
    terms: &wholepact_authority::offline::OfflineAuthorizationTerms,
    born: bool,
) -> ImportResult<wire::MessageContext> {
    terms.validate().map_err(|_| TransportError::WrongContext)?;
    let prefix = if born {
        "born-offline-intent"
    } else {
        "offline-intent"
    };
    Ok(wire::MessageContext {
        network_profile_id: terms.network_profile_id.clone(),
        agreement_id: terms.agreement_id.clone(),
        proposal_id: terms.proposal_id.clone(),
        proposal_revision: terms.proposal_revision,
        sender_id: format!("{prefix}:{}", terms.offline_signer_key_digest),
        recipient_id: format!("{prefix}:{}", terms.offline_policy_digest),
        artifact_kind: if born {
            wire::ArtifactKind::BornOfflineIntentV1
        } else {
            wire::ArtifactKind::OfflineReservationIntent
        },
    })
}
fn require_same_intent_context(
    draft: &wire::MessageContext,
    complete: &wire::MessageContext,
) -> ImportResult<()> {
    if serde_json::to_vec(draft).map_err(|_| TransportError::Malformed)?
        != serde_json::to_vec(complete).map_err(|_| TransportError::Malformed)?
    {
        return Err(TransportError::WrongContext);
    }
    Ok(())
}
#[cfg(test)]
#[path = "original_import/draft_context_tests.rs"]
mod draft_context_tests;
