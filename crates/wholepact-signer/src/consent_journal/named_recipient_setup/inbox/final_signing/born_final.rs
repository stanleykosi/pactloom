//! Purpose-distinct native-born final continuation. The original construction,
//! birth and enrollment are obtained from actual complete authenticated replay.
//! Nothing here converts a born account into legacy OfflineV1 authority.
use super::super::super::super::named_recipient_records::BornNamedRecipientFinalReviewV1;
use super::super::born_admission_input::{PreparedBornAdmissionInputV1, prepare_admission_input};
use super::super::born_original_history::authenticate_admission;
use super::*;

pub(crate) struct PreparedBornNamedRecipientSigning {
    operation: NamedRecipientOperation,
    profile: LiveNamedRecipientProfile,
    original: NamedRecipientOriginalRecordV1,
    final_review: BornNamedRecipientFinalReviewV1,
    admission_input: PreparedBornAdmissionInputV1,
    created: Instant,
    deadline: Instant,
    wall_floor: u64,
    digest: String,
    display: String,
}
impl LiveNamedRecipientProfile {
    pub(crate) fn prepare_born_final_signing(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        client: &AuthorityClient,
        authorization_id: &str,
        operation: NamedRecipientOperation,
    ) -> ImportResult<PreparedBornNamedRecipientSigning> {
        operation.check()?;
        require_profile_owner(self, journal)?;
        id(authorization_id).map_err(unavailable)?;
        let created = Instant::now();
        let wall_floor = wall_ms()?;
        let reference = original_reference(journal, self, authorization_id)?;
        let (record, retained) = load_profile_and_original(journal, self, &reference)?;
        let original = retained.record;
        let origin = original
            .born_origin
            .as_ref()
            .ok_or(TransportError::AuthorityUnavailable)?;
        let deadline = created
            .checked_add(
                Duration::from_millis(
                    original
                        .validity_expires_ms
                        .min(original.reservation_request.admission_expires_at_ms)
                        .checked_sub(wall_floor)
                        .filter(|n| *n > 0)
                        .ok_or(TransportError::InvalidTime)?,
                )
                .min(Duration::from_secs(120)),
            )
            .ok_or(TransportError::InvalidTime)?
            .min(operation.deadline());
        let current = || {
            operation.check()?;
            check_current(self, deadline, wall_floor, &original)
        };
        current()?;
        let own = retained_own_policy(&original, vault)?;
        let assertion_digest = assertion_receipt_digest(journal, self, &original)?;
        let assertion = self
            .recover_assertion_import(
                journal,
                session,
                vault,
                &original.reference,
                &own,
                &assertion_digest,
            )?
            .ok_or(TransportError::Authentication)?;
        require_assertion_original(&assertion, &original)?;
        let history = client
            .reconcile_history_checked_until(deadline, || {
                current().map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(unavailable)?;
        let admission = authenticate_admission(self, &original, &history, client)?;
        let admission_input =
            prepare_admission_input(self, &original, &history, client, deadline, current)?;
        let records = journal
            .acquire_preconstruction_records(&record.enrollment_ref, &record.manifest_ref, session)
            .map_err(unavailable)?;
        require_own_context(self, &original, &own, vault, &records)?;
        origin
            .require_actual_signer(
                &*journal.connection.lock().map_err(unavailable)?,
                &record,
                records.enrollment(),
            )
            .map_err(unavailable)?;
        origin
            .checkpoint_receipt
            .require_retained(&*journal.connection.lock().map_err(unavailable)?)
            .map_err(unavailable)?;
        if records.sponsor_required() || records.sponsor_policy().is_some() {
            return Err(TransportError::AuthorityUnavailable);
        }
        require_not_started(journal, authorization_id)?;
        let sequence =
            next_return_sequence(&*journal.connection.lock().map_err(unavailable)?, &original)?;
        let end = original
            .validity_expires_ms
            .min(original.reservation_request.admission_expires_at_ms)
            / 1000;
        let start = admission.reserved.reserved_at_ms / 1000;
        if end <= start {
            return Err(TransportError::InvalidTime);
        }
        let message = digest(
            "wholepact:born-named-recipient-return-message:v1",
            &(
                &original.reference,
                origin.request.request_digest().map_err(unavailable)?,
            ),
        )
        .map_err(unavailable)?;
        let mut final_review = BornNamedRecipientFinalReviewV1 {
            schema_version: 1,
            admission,
            origin_digest: origin.digest().map_err(unavailable)?,
            witness: history.disclosure().clone(),
            history_digest: history.history_digest().map_err(unavailable)?,
            assertion_envelope_digest: assertion_digest,
            admission_receipt: admission_input.receipt().clone(),
            native_review_digest: String::new(),
            consent_reference: String::new(),
            reviewed_at_ms: 0,
            return_message_id: message[..32].into(),
            return_sequence: sequence,
            return_issued_at: i64::try_from(start).map_err(unavailable)?,
            return_expires_at: i64::try_from(end).map_err(unavailable)?,
        };
        let digest = digest(
            "wholepact:native-born-named-recipient-final-signing:v1",
            &(
                &original.reference,
                &original.terms,
                &original.own_expectations,
                &final_review,
                self.source.entry_digest(),
            ),
        )
        .map_err(unavailable)?;
        final_review.native_review_digest = digest.clone();
        let display = format!(
            "FINAL EXACT NATIVE-BORN NAMED-MODE SIGNING CONSENT\nAccount: {}\nAuthorization: {}\nOriginal: {}\nBorn origin: {}\nBirth enrollment: {}\nInstalled artifacts: {}\nExact V3 construction continuation: {}\nOuter born request: {}\nInner reservation request: {}\nOriginal full artifact: {}\nReviewed canonical artifact: {}\nEffects: {}\nMaximum own debit: {} zatoshis\nOwn fee share: {} zatoshis\nTransaction fee: {} zatoshis\nExpiry height: {}\nWitness: {}\nComplete history: {}\nAuthenticated original admission ciphertext: {}\nExact independently retained own effects:\n{}\n\nThe original V3 construction exposure remains held; this continuation does not allocate a replacement payment or clear any exposure. Birth lineage does not establish independent peer ownership. The selected verifier establishes peer labels and can hide an own-controlled input under a peer label. Selected-own checks do not establish complete own-input coverage.\nApproval signs only selected own indices for this exact original born admission after a fresh purpose-distinct authenticated clock observation. The original authenticated receipt and Started are retained atomically before key use. Any failure after Started is uncertain and never permits automatic re-signing.\nThe return is encrypted only to key {} with immutable message {}, sequence {}, and original window {}..{} seconds. It contains own signatures and original commitments, not peer FVKs or the full transaction. File delivery requires a separate decision.\nCurrent chain tip, current spendability, mempool conflicts, later reorganization, remote revocation after the last observation and uniqueness across clones remain unknown. Online current validation is required before submission. This is not payment or settlement.\nExact native review: {}",
            original.terms.account_id,
            authorization_id,
            original.reference,
            final_review.origin_digest,
            origin.request.enrollment_digest,
            origin.request.artifact_binding_digest,
            serde_json::to_string(&origin.request.construction_link).map_err(unavailable)?,
            origin.request.request_digest().map_err(unavailable)?,
            original.reservation_request_digest,
            original.original_artifact_digest,
            original.canonical_artifact_digest,
            original.terms.effects_digest,
            original.terms.maximum_debit_zatoshis,
            original.terms.fee_share_zatoshis,
            original.terms.transaction_fee_zatoshis,
            original.terms.transaction_expiry_height,
            final_review.witness.witness_id,
            final_review.history_digest,
            admission_input.envelope_digest(),
            serde_json::to_string_pretty(&original.own_expectations).map_err(unavailable)?,
            original.terms.return_recipient_key_digest,
            final_review.return_message_id,
            sequence,
            final_review.return_issued_at,
            final_review.return_expires_at,
            digest
        );
        current()?;
        records.check_current().map_err(unavailable)?;
        Ok(PreparedBornNamedRecipientSigning {
            operation,
            profile: LiveNamedRecipientProfile {
                record,
                journal: self.journal.clone(),
                source: self.source.clone(),
            },
            original,
            final_review,
            admission_input,
            created,
            deadline,
            wall_floor,
            digest,
            display,
        })
    }
}
impl PreparedBornNamedRecipientSigning {
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn display(&self) -> &str {
        &self.display
    }
    pub(crate) fn approve_and_sign(
        mut self,
        decision: NativeDecision,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        client: &AuthorityClient,
    ) -> ImportResult<NamedRecipientSigningOutcome> {
        require_profile_owner(&self.profile, journal)?;
        if decision.binding() != &self.profile.source
            || decision.reviewed_digest() != self.digest
            || decision.consumed_at().elapsed() >= Duration::from_secs(120)
            || self.created.elapsed() >= Duration::from_secs(120)
        {
            return Err(TransportError::DisclosureDenied);
        }
        let current = || {
            self.operation.check()?;
            check_current(
                &self.profile,
                self.deadline,
                self.wall_floor,
                &self.original,
            )
        };
        current()?;
        let history = client
            .reconcile_history_checked_until(self.deadline, || {
                current().map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(unavailable)?;
        let admission = authenticate_admission(&self.profile, &self.original, &history, client)?;
        if admission != self.final_review.admission
            || history.disclosure() != &self.final_review.witness
        {
            return Err(TransportError::WrongContext);
        }
        let scope =
            wholepact_authority::born_offline_clock_v1::BornOfflineClockScopeV1::from_descriptor(
                &admission,
            )
            .map_err(unavailable)?;
        let clock = client
            .observe_born_offline_admission_time_v1(&scope, self.deadline, || {
                current().map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(unavailable)?;
        if clock.authenticated_witness_certificate_digest()
            != self.profile.record.witness_certificate_digest
        {
            return Err(TransportError::Authentication);
        }
        let own = retained_own_policy(&self.original, vault)?;
        let assertion = self
            .profile
            .recover_assertion_import(
                journal,
                session,
                vault,
                &self.original.reference,
                &own,
                &self.final_review.assertion_envelope_digest,
            )?
            .ok_or(TransportError::Authentication)?;
        require_assertion_original(&assertion, &self.original)?;
        let records = journal
            .acquire_preconstruction_records(
                &self.profile.record.enrollment_ref,
                &self.profile.record.manifest_ref,
                session,
            )
            .map_err(unavailable)?;
        require_own_context(&self.profile, &self.original, &own, vault, &records)?;
        let origin = self
            .original
            .born_origin
            .as_ref()
            .ok_or(TransportError::AuthorityUnavailable)?;
        origin
            .require_actual_signer(
                &*journal.connection.lock().map_err(unavailable)?,
                &self.profile.record,
                records.enrollment(),
            )
            .map_err(unavailable)?;
        origin
            .checkpoint_receipt
            .require_retained(&*journal.connection.lock().map_err(unavailable)?)
            .map_err(unavailable)?;
        if records.sponsor_required() || records.sponsor_policy().is_some() {
            return Err(TransportError::AuthorityUnavailable);
        }
        let check = || {
            records.check_current().map_err(unavailable)?;
            clock.check_current(&scope).map_err(unavailable)?;
            current()
        };
        check()?;
        self.final_review.reviewed_at_ms = clock.witness_time_ms();
        self.final_review.consent_reference =
            self.final_review.reference_digest().map_err(unavailable)?;
        let started = NamedRecipientStartedRecordV1 {
            final_review: None,
            born_final_review: Some(self.final_review.clone()),
            schema_version: 1,
            authorization_id: self.original.terms.authorization_id.clone(),
            original_ref: self.original.reference.clone(),
            native_review_digest: self.digest.clone(),
            native_origin_digest: self.profile.source.entry_digest().into(),
            admission_request_digest: origin.request.request_digest().map_err(unavailable)?,
            authenticated_package_digest: self.original.terms.review_package_digest.clone(),
            original_deadline_ms: self
                .original
                .reservation_request
                .admission_expires_at_ms
                .min(self.original.validity_expires_ms),
        };
        let committed = commit_started(
            journal,
            &self.profile,
            &self.original,
            &started,
            &check,
            |tx| {
                origin
                    .require_actual_signer(tx, &self.profile.record, records.enrollment())
                    .map_err(unavailable)?;
                origin
                    .checkpoint_receipt
                    .require_retained(tx)
                    .map_err(unavailable)?;
                self.admission_input
                    .commit_into(tx, &self.profile, &self.original, &records)
            },
        )?;
        // The same maintained adapter as the legacy path consumes an actual
        // committed-Started capability. No evidence DTO can invoke it alone.
        (|| {
            let bytes = sign_committed_own(
                committed,
                &self.profile,
                &self.original,
                &own,
                &assertion,
                vault,
                &check,
            )?;
            let (projection_digest, envelope) =
                seal_signature_return(&self.profile, &self.original, &started, &bytes)?;
            check()?;
            let result = NamedRecipientResultRecordV1 {
                encrypted_return: Some(NamedRecipientEncryptedReturnV1 {
                    schema_version: 1,
                    signed_artifact_digest: hex::encode(Sha256::digest(&*bytes)),
                    projection_digest,
                    envelope_digest: envelope_commitment(envelope.as_bytes())?,
                    envelope_hex: hex::encode(envelope.as_bytes()),
                }),
                schema_version: 1,
                authorization_id: started.authorization_id.clone(),
                original_ref: started.original_ref.clone(),
                started_digest: started.marker_digest().map_err(unavailable)?,
                result_digest: hex::encode(Sha256::digest(&*bytes)),
                result_hex: hex::encode(&*bytes),
            };
            result
                .validate(&started, &self.original)
                .map_err(unavailable)?;
            commit_result(journal, &self.profile, &started, &result, &check)?;
            Ok(NamedRecipientSigningOutcome {
                authorization_id: result.authorization_id,
                original_ref: result.original_ref,
                result_digest: result.result_digest,
                return_envelope_digest: result
                    .encrypted_return
                    .ok_or(TransportError::WrongContext)?
                    .envelope_digest,
            })
        })()
        .map_err(|_: TransportError| TransportError::ImportCommittedButUnavailable)
    }
}
