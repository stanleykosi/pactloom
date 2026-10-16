//! Concrete named-mode recipient continuation. The actual native profile/session,
//! authenticated complete witness history and retained assertion own this path.
//! Neither serialized history nor a package signature is a spending capability.
use super::super::super::named_intent_transport as wire;
use super::super::super::named_recipient_records::{
    NamedRecipientEncryptedReturnV1, NamedRecipientFinalReviewV1, NamedRecipientResultRecordV1,
    NamedRecipientStartedRecordV1,
};
use super::*;
use orchard::keys::SpendAuthorizingKey;
use pczt::{Pczt, roles::signer::Signer};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use wholepact_authority::{
    AuthorityClient, OwnerControl, ReconciledAuthorityHistory, ReservationEvidenceRef,
    WriterStatus, offline::OfflineAuthorizationAdmission,
};
use wholepact_offline_bridge::{NamedVerifierPackageV1, inspect_named_verifier_return};
use wholepact_protocol::own_effects::{OwnInputExpectation, OwnOutputExpectation};

/// Cancellation carries no authority. The real native source and session remain
/// independently required. A UI owner retains this nonrenewing operation while
/// a worker owns I/O, so blur/cancel never waits for network or database work.
#[derive(Clone)]
pub(crate) struct NamedRecipientOperation {
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    deadline: Instant,
}
impl NamedRecipientOperation {
    pub(crate) fn new() -> Self {
        Self {
            cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(120),
        }
    }
    pub(crate) fn revoke(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
    }
    pub(crate) fn check(&self) -> ImportResult<()> {
        if self.cancelled.load(std::sync::atomic::Ordering::Acquire)
            || Instant::now() >= self.deadline
        {
            Err(TransportError::DisclosureDenied)
        } else {
            Ok(())
        }
    }
}

/// An exact final review, not yet approved. Source and originals cannot be
/// replaced after presentation. Only the actual native surface can consume it.
pub(crate) struct PreparedNamedRecipientSigning {
    operation: NamedRecipientOperation,
    profile: LiveNamedRecipientProfile,
    original: NamedRecipientOriginalRecordV1,
    assertion_envelope_digest: String,
    final_review: NamedRecipientFinalReviewV1,
    created: Instant,
    deadline: Instant,
    wall_floor: u64,
    digest: String,
    display: String,
}
/// Commitment-only outcome. Raw signatures never escape before durable retention.
pub(crate) struct NamedRecipientSigningOutcome {
    pub(crate) authorization_id: String,
    pub(crate) original_ref: String,
    pub(crate) result_digest: String,
    pub(crate) return_envelope_digest: String,
}

impl LiveNamedRecipientProfile {
    pub(crate) fn prepare_final_signing(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        client: &AuthorityClient,
        authorization_id: &str,
        operation: NamedRecipientOperation,
    ) -> ImportResult<PreparedNamedRecipientSigning> {
        operation.check()?;
        require_profile_owner(self, journal)?;
        id(authorization_id).map_err(unavailable)?;
        let created = Instant::now();
        let wall_floor = wall_ms()?;
        let original_ref = original_reference(journal, self, authorization_id)?;
        let (record, retained) = load_profile_and_original(journal, self, &original_ref)?;
        let original = retained.record;
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
            .min(operation.deadline);
        let own = retained_own_policy(&original, vault)?;
        let envelope_digest = assertion_receipt_digest(journal, self, &original)?;
        let assertion = self
            .recover_assertion_import(
                journal,
                session,
                vault,
                &original.reference,
                &own,
                &envelope_digest,
            )?
            .ok_or(TransportError::Authentication)?;
        require_assertion_original(&assertion, &original)?;
        // Remote reads happen before any native publication fence or database lock.
        let history = client
            .reconcile_history_checked_until(deadline, || {
                operation
                    .check()
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)?;
                self.source
                    .check_current()
                    .map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(unavailable)?;
        let mut final_review = authenticate_original_history(self, &original, &history, client)?;
        final_review.assertion_envelope_digest = envelope_digest.clone();
        let records = journal
            .acquire_preconstruction_records(&record.enrollment_ref, &record.manifest_ref, session)
            .map_err(unavailable)?;
        require_own_context(self, &original, &own, vault, &records)?;
        // Sponsor key-use policy is not silently weakened into a fixed contribution.
        if records.sponsor_required() || records.sponsor_policy().is_some() {
            return Err(TransportError::AuthorityUnavailable);
        }
        require_not_started(journal, authorization_id)?;
        final_review.return_sequence =
            next_return_sequence(&*journal.connection.lock().map_err(unavailable)?, &original)?;
        let digest = digest(
            "wholepact:native-named-recipient-final-signing:v1",
            &(
                &original.reference,
                &original.terms,
                &original.own_expectations,
                &final_review.admission,
                &final_review.enrollment,
                &final_review.account_policy,
                &final_review.witness,
                &final_review.history_digest,
                &envelope_digest,
                &final_review.return_message_id,
                final_review.return_sequence,
                final_review.return_issued_at,
                final_review.return_expires_at,
                self.source.entry_digest(),
            ),
        )
        .map_err(unavailable)?;
        final_review.native_review_digest = digest.clone();
        let display = format!(
            "FINAL EXACT NAMED-MODE SIGNING CONSENT\nAccount: {}\nAuthorization: {}\nOriginal: {}\nSelected verifier key: {}\nOriginal full artifact: {}\nReviewed canonical artifact: {}\nEffects: {}\nMaximum own debit: {} zatoshis\nOwn fee share: {} zatoshis\nTransaction fee: {} zatoshis\nExpiry height: {}\nWitness: {}\nAuthenticated original admission: {}\nComplete history: {}\nExact independently retained own effects:\n{}\n\nThe selected verifier, not independent multi-owner verification, establishes peer input ownership and return attribution. A dishonest verifier can hide an own-controlled input under a peer label. Selected-own checks do not establish complete own-input coverage.\nApproval uses only this exact admission and signs only selected own indices. Started is durably retained before any key use. Failure after Started is uncertain and never permits automatic re-signing.\nThe return is encrypted only to key {} with message {} and original window {}..{} seconds. It contains own signatures and exact operation/effect commitments, not peer FVKs or the full transaction. It is retained locally; file delivery requires a separate decision.\nCurrent chain tip, current input spendability, mempool conflicts, later reorganization, remote revocation after the last observation, and global uniqueness across cloned software remain unknown. Previously admitted exposure is never cleared by cancellation, expiration or local failure. Online current validation remains required before submission. This is not payment or settlement.\nOriginal return stream sequence: {}\nExact native review: {}",
            original.terms.account_id,
            original.terms.authorization_id,
            original.reference,
            hex::encode(self.record.verifier_signing_public_key),
            original.original_artifact_digest,
            original.canonical_artifact_digest,
            original.terms.effects_digest,
            original.terms.maximum_debit_zatoshis,
            original.terms.fee_share_zatoshis,
            original.terms.transaction_fee_zatoshis,
            original.terms.transaction_expiry_height,
            final_review.witness.witness_id,
            final_review.admission.request_digest,
            final_review.history_digest,
            serde_json::to_string_pretty(&original.own_expectations).map_err(unavailable)?,
            original.terms.return_recipient_key_digest,
            final_review.return_message_id,
            final_review.return_issued_at,
            final_review.return_expires_at,
            final_review.return_sequence,
            digest
        );
        operation.check()?;
        check_current(self, deadline, wall_floor, &original)?;
        Ok(PreparedNamedRecipientSigning {
            operation,
            profile: LiveNamedRecipientProfile {
                record,
                journal: self.journal.clone(),
                source: self.source.clone(),
            },
            original,
            assertion_envelope_digest: envelope_digest,
            final_review,
            created,
            deadline,
            wall_floor,
            digest,
            display,
        })
    }
}
impl PreparedNamedRecipientSigning {
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
        let authenticated =
            authenticate_original_history(&self.profile, &self.original, &history, client)?;
        // A later complete head is allowed only if the identical original remains
        // present and non-quarantined. No new request or amended admission is used.
        if authenticated.admission != self.final_review.admission
            || authenticated.enrollment != self.final_review.enrollment
            || authenticated.account_policy != self.final_review.account_policy
            || authenticated.witness != self.final_review.witness
        {
            return Err(TransportError::WrongContext);
        }
        let scope = wholepact_authority::offline_clock_v1::OfflineClockScopeV1::from_descriptor(
            &authenticated.admission,
        )
        .map_err(unavailable)?;
        let clock = client
            .observe_offline_admission_time_v1(&scope, self.deadline, || {
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
                &self.assertion_envelope_digest,
            )?
            .ok_or(TransportError::Authentication)?;
        require_assertion_original(&assertion, &self.original)?;
        let package_bytes = assertion
            .artifact()
            .fields()
            .first()
            .ok_or(TransportError::WrongContext)?
            .bytes();
        let package = NamedVerifierPackageV1::parse(package_bytes)?;
        let records = journal
            .acquire_preconstruction_records(
                &self.profile.record.enrollment_ref,
                &self.profile.record.manifest_ref,
                session,
            )
            .map_err(unavailable)?;
        require_own_context(&self.profile, &self.original, &own, vault, &records)?;
        if records.sponsor_required() || records.sponsor_policy().is_some() {
            return Err(TransportError::AuthorityUnavailable);
        }
        let check = || {
            records.check_current().map_err(unavailable)?;
            clock.check_current(&scope).map_err(unavailable)?;
            current()
        };
        check()?;
        // Final consent is historical data only after this actual decision. The
        // live decision is consumed, not reconstituted from these fields.
        self.final_review.reviewed_at_ms = clock.witness_time_ms();
        self.final_review.consent_reference =
            self.final_review.reference_digest().map_err(unavailable)?;
        let started = NamedRecipientStartedRecordV1 {
            final_review: Some(self.final_review.clone()),
            schema_version: 1,
            authorization_id: self.original.terms.authorization_id.clone(),
            original_ref: self.original.reference.clone(),
            native_review_digest: self.digest.clone(),
            native_origin_digest: self.profile.source.entry_digest().into(),
            admission_request_digest: self.original.reservation_request_digest.clone(),
            authenticated_package_digest: self.original.terms.review_package_digest.clone(),
            original_deadline_ms: self
                .original
                .reservation_request
                .admission_expires_at_ms
                .min(self.original.validity_expires_ms),
        };
        started.validate(&self.original).map_err(unavailable)?;
        commit_started(journal, &self.profile, &self.original, &started, &check)?;
        // Every failure after attempted Started is ambiguous, never retryable key
        // authority. No raw signature escapes this closure on any error.
        #[cfg(test)]
        let mut phase = "parse reviewed artifact";
        let result = (|| {
            check()?;
            let parsed = Pczt::parse(&package.recipient_artifact).map_err(unavailable)?;
            if own.own_inputs.iter().any(|i| {
                parsed
                    .ironwood()
                    .actions()
                    .get(i.action_index)
                    .is_none_or(|a| a.spend().spend_auth_sig().is_some())
            }) {
                return Err(TransportError::WrongContext);
            }
            #[cfg(test)]
            {
                phase = "initialize maintained signer";
            }
            // Canonical named artifacts intentionally omit every real-input FVK.
            // The high-level signer requires an embedded FVK. Use the maintained
            // preverified role instead, after exact own-effects verification, and
            // repeat nullifier/rk checks with this account's actual FVK below.
            let sighash = Signer::new(parsed.clone())
                .map_err(unavailable)?
                .shielded_sighash();
            if hex::encode(sighash) != assertion.inspection().own().inspection().shielded_sighash()
                || hex::encode(sighash) != self.original.terms.effects_digest
                || *parsed.global().tx_modifiable() != 0
            {
                return Err(TransportError::WrongContext);
            }
            #[cfg(test)]
            {
                phase = "maintained selected-own signing";
            }
            let signed = pczt::roles::low_level_signer::Signer::new(parsed)
                .sign_ironwood_with::<MaintainedOwnSignError, _>(|_, bundle, tx_modifiable| {
                    if *tx_modifiable != 0 {
                        return Err(MaintainedOwnSignError);
                    }
                    bundle
                        .verify_cross_address_restriction()
                        .map_err(|_| MaintainedOwnSignError)?;
                    for input in &own.own_inputs {
                        let action = bundle
                            .actions_mut()
                            .get_mut(input.action_index)
                            .ok_or(MaintainedOwnSignError)?;
                        action
                            .spend()
                            .verify_nullifier(Some(&own.own_fvk))
                            .map_err(|_| MaintainedOwnSignError)?;
                        action
                            .spend()
                            .verify_rk(Some(&own.own_fvk))
                            .map_err(|_| MaintainedOwnSignError)?;
                        if action.spend().spend_auth_sig().is_some() {
                            return Err(MaintainedOwnSignError);
                        }
                        // One bounded maintained key operation, not remote/SQLite I/O.
                        let _key_use = self
                            .profile
                            .source
                            .publication_lease()
                            .map_err(|_| MaintainedOwnSignError)?;
                        check().map_err(|_| MaintainedOwnSignError)?;
                        let key = vault
                            .account()
                            .spending_key()
                            .map_err(|_| MaintainedOwnSignError)?;
                        let ask = SpendAuthorizingKey::from(&key);
                        action
                            .sign(sighash, &ask, UnwrapErr(SysRng))
                            .map_err(|_| MaintainedOwnSignError)?;
                    }
                    Ok(())
                })
                .map_err(unavailable)?
                .finish();
            #[cfg(test)]
            {
                phase = "serialize maintained signed artifact";
            }
            let bytes = Zeroizing::new(
                pczt::v2::Pczt::try_from(signed.clone())
                    .map_err(unavailable)?
                    .serialize(),
            );
            #[cfg(test)]
            {
                phase = "verify exact own signature delta";
            }
            let verified =
                inspect_named_verifier_return(package_bytes, &bytes, assertion.inspection())?;
            if verified.reviewed_artifact_digest() != self.original.canonical_artifact_digest
                || verified.shielded_sighash() != self.original.terms.effects_digest
            {
                return Err(TransportError::WrongContext);
            }
            check()?;
            #[cfg(test)]
            {
                phase = "seal exact return projection";
            }
            let (projection_digest, envelope) =
                seal_signature_return(&self.profile, &self.original, &started, &bytes)?;
            check()?;
            let returned = NamedRecipientEncryptedReturnV1 {
                schema_version: 1,
                signed_artifact_digest: hex::encode(Sha256::digest(&*bytes)),
                projection_digest,
                envelope_digest: envelope_commitment(envelope.as_bytes())?,
                envelope_hex: hex::encode(envelope.as_bytes()),
            };
            let result = NamedRecipientResultRecordV1 {
                encrypted_return: Some(returned),
                schema_version: 1,
                authorization_id: started.authorization_id.clone(),
                original_ref: started.original_ref.clone(),
                started_digest: started.marker_digest().map_err(unavailable)?,
                result_digest: hex::encode(Sha256::digest(&*bytes)),
                result_hex: hex::encode(&*bytes),
            };
            #[cfg(test)]
            {
                phase = "validate retained result record";
            }
            result
                .validate(&started, &self.original)
                .map_err(unavailable)?;
            #[cfg(test)]
            {
                phase = "commit exact result";
            }
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
        })();
        result.map_err(|error: TransportError| {
            // Test-only phase labels and coarse error kinds contain no private
            // artifact, key, account identity or consent material.
            #[cfg(test)]
            eprintln!("named final continuation failed at {phase}: {error:?}");
            #[cfg(not(test))]
            let _ = error;
            TransportError::ImportCommittedButUnavailable
        })
    }
}

// Nominal local adapter error only. It conveys no signing permission or detail
// from private maintained parse state across the recipient boundary.
struct MaintainedOwnSignError;
impl From<pczt::roles::low_level_signer::OrchardParseError> for MaintainedOwnSignError {
    fn from(_: pczt::roles::low_level_signer::OrchardParseError) -> Self {
        Self
    }
}

fn original_reference(
    journal: &SignerConsentJournal,
    profile: &LiveNamedRecipientProfile,
    id: &str,
) -> ImportResult<String> {
    let c = journal.connection.lock().map_err(unavailable)?;
    c.query_row("SELECT reference FROM signer_named_recipient_originals WHERE profile_ref=?1 AND authorization_id=?2",params![profile.record.reference,id],|r|r.get(0)).map_err(unavailable)
}
fn require_not_started(journal: &SignerConsentJournal, authorization: &str) -> ImportResult<()> {
    let c = journal.connection.lock().map_err(unavailable)?;
    require_unstarted_connection(&c, authorization)
}
fn require_unstarted_connection(c: &rusqlite::Connection, authorization: &str) -> ImportResult<()> {
    let exists:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM signer_named_recipient_started WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_named_recipient_results WHERE authorization_id=?1)",[authorization],|r|r.get(0)).map_err(unavailable)?;
    if exists {
        Err(TransportError::ImportCommittedButUnavailable)
    } else {
        Ok(())
    }
}
fn wall_ms() -> ImportResult<u64> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(unavailable)?
            .as_millis(),
    )
    .map_err(unavailable)
}
fn check_current(
    profile: &LiveNamedRecipientProfile,
    deadline: Instant,
    floor: u64,
    original: &NamedRecipientOriginalRecordV1,
) -> ImportResult<()> {
    check_setup_current(&profile.source, deadline).map_err(unavailable)?;
    let now = wall_ms()?;
    if now < floor
        || now < original.validity_not_before_ms
        || now >= original.validity_expires_ms
        || now < original.reservation_request.requested_at_ms
        || now >= original.reservation_request.admission_expires_at_ms
    {
        return Err(TransportError::InvalidTime);
    }
    Ok(())
}
fn authenticate_original_history(
    profile: &LiveNamedRecipientProfile,
    original: &NamedRecipientOriginalRecordV1,
    history: &ReconciledAuthorityHistory,
    client: &AuthorityClient,
) -> ImportResult<NamedRecipientFinalReviewV1> {
    let witness = client.disclosure_descriptor();
    if history.disclosure()!=&witness || witness.pinned_server_certificate_digest!=profile.record.witness_certificate_digest
        || witness.account_id!=profile.record.account_id || witness.network_profile_id!=original.terms.network_profile_id
        || history.snapshot().writer_status==WriterStatus::Quarantined
        || history.account_use_history().exclusion().is_some()
        // Born accounts need their separate native namespace owner; legacy final
        // composition never converts them to legacy semantics.
        || history.account_use_history().genesis().is_some()
    {
        return Err(TransportError::AuthorityUnavailable);
    }
    history
        .require_construction_v2_only()
        .map_err(unavailable)?;
    let enrollment = history
        .offline_enrollment_operation(&original.terms.offline_policy_digest)
        .map_err(unavailable)?
        .ok_or(TransportError::Authentication)?;
    let OwnerControl::EnrollOfflinePolicy { policy, .. } = &enrollment.control else {
        return Err(TransportError::Authentication);
    };
    let admissions: Vec<&OfflineAuthorizationAdmission> = history
        .reservation_evidence()
        .filter_map(|r| match r {
            ReservationEvidenceRef::OfflineV1(a)
                if a.request.operation_id == original.reservation_request.operation_id =>
            {
                Some(a)
            }
            _ => None,
        })
        .collect();
    if admissions.len() != 1 {
        return Err(TransportError::Authentication);
    }
    let admission = admissions[0];
    admission
        .matches_request(&original.reservation_request)
        .map_err(unavailable)?;
    admission
        .validate_reserved_policy_bounds(history.account_policy(), policy)
        .map_err(unavailable)?;
    if admission.request_digest != original.reservation_request_digest
        || admission.witness_id != witness.witness_id
        || admission.witness_policy_digest != witness.policy_digest
        || !history.contains_head(&admission.committed_head)
        || !history.contains_head(&original.reservation_request.expected_head)
        || policy.witness_certificate_digest != profile.record.witness_certificate_digest
        || policy.witness_transport_key_digest
            != super::super::super::named_recipient_records::transport_fingerprint(
                &profile.record.witness_transport_public_key,
            )
        || policy.offline_signer_key_digest != original.terms.offline_signer_key_digest
        || policy.return_recipient_key_digest != original.terms.return_recipient_key_digest
    {
        return Err(TransportError::WrongContext);
    }
    let end = original
        .validity_expires_ms
        .min(admission.request.admission_expires_at_ms)
        / 1000;
    let start = admission.reserved_at_ms / 1000;
    if end <= start {
        return Err(TransportError::InvalidTime);
    }
    let message = digest(
        "wholepact:named-recipient-return-message:v1",
        &(&original.reference, &admission.request_digest),
    )
    .map_err(unavailable)?;
    Ok(NamedRecipientFinalReviewV1 {
        schema_version: 1,
        admission: admission.clone(),
        enrollment: policy.clone(),
        account_policy: history.account_policy().clone(),
        witness,
        history_digest: history.history_digest().map_err(unavailable)?,
        assertion_envelope_digest: String::new(),
        native_review_digest: String::new(),
        consent_reference: String::new(),
        reviewed_at_ms: 0,
        return_message_id: message[..32].into(),
        return_sequence: 0,
        return_issued_at: i64::try_from(start).map_err(unavailable)?,
        return_expires_at: i64::try_from(end).map_err(unavailable)?,
    })
}
fn retained_own_policy(
    original: &NamedRecipientOriginalRecordV1,
    vault: &AccountVault,
) -> ImportResult<OwnEffectsPolicy> {
    let e = &original.own_expectations;
    fn bytes<const N: usize>(s: &str) -> ImportResult<[u8; N]> {
        hex::decode(s)
            .map_err(unavailable)?
            .try_into()
            .map_err(|_| TransportError::WrongContext)
    }
    let own_fvk = vault.account().fvk().map_err(unavailable)?;
    if hex::encode(Sha256::digest(own_fvk.to_bytes())) != e.full_viewing_key_digest {
        return Err(TransportError::WrongContext);
    }
    Ok(OwnEffectsPolicy {
        account_id: original.terms.account_id.clone(),
        own_fvk,
        manifest_digest: bytes(&e.manifest_digest)?,
        anchor: bytes(&e.anchor)?,
        expiry_height: e.expiry_height,
        maximum_selected_net_debit_zatoshis: e.maximum_selected_net_debit_zatoshis,
        exact_selected_net_debit_zatoshis: e.exact_selected_net_debit_zatoshis,
        declared_fee_share_zatoshis: e.declared_fee_share_zatoshis,
        exact_transaction_fee_zatoshis: e.exact_transaction_fee_zatoshis,
        own_inputs: e
            .own_inputs
            .iter()
            .map(|i| {
                Ok(OwnInputExpectation {
                    action_index: i.action_index as usize,
                    nullifier: bytes(&i.nullifier)?,
                    value_zatoshis: i.value_zatoshis,
                })
            })
            .collect::<ImportResult<_>>()?,
        outputs: e
            .outputs
            .iter()
            .map(|o| {
                Ok(OwnOutputExpectation {
                    action_index: o.action_index as usize,
                    receiver: Option::from(orchard::Address::from_raw_address_bytes(&bytes(
                        &o.receiver_hex,
                    )?))
                    .ok_or(TransportError::WrongContext)?,
                    value_zatoshis: o.value_zatoshis,
                    memo: bytes(&o.memo_hex)?,
                    purpose: match o.purpose {
                        NamedRecipientOutputPurposeV1::OwnReturn => OwnOutputPurpose::OwnReturn,
                        NamedRecipientOutputPurposeV1::Recipient => OwnOutputPurpose::Recipient,
                        NamedRecipientOutputPurposeV1::PeerReturnUnverified => {
                            OwnOutputPurpose::PeerReturnUnverified
                        }
                    },
                })
            })
            .collect::<ImportResult<_>>()?,
    })
}
fn assertion_receipt_digest(
    journal: &SignerConsentJournal,
    profile: &LiveNamedRecipientProfile,
    original: &NamedRecipientOriginalRecordV1,
) -> ImportResult<String> {
    let t = &original.terms;
    let context = wire::MessageContext {
        network_profile_id: t.network_profile_id.clone(),
        agreement_id: t.agreement_id.clone(),
        proposal_id: t.proposal_id.clone(),
        proposal_revision: t.proposal_revision,
        sender_id: hex::encode(Sha256::digest(profile.record.verifier_signing_public_key)),
        recipient_id: profile.record.account_id.clone(),
        artifact_kind: wire::ArtifactKind::NamedVerifierAssertion,
    };
    let stream = wire::stream_digest(&context).map_err(unavailable)?;
    let slot = wire::immutable_slot_digest(&context)
        .map_err(unavailable)?
        .ok_or(TransportError::WrongContext)?;
    let c = journal.connection.lock().map_err(unavailable)?;
    let mut q=c.prepare("SELECT envelope_digest FROM signer_named_recipient_receipts WHERE profile_ref=?1 AND stream=?2 AND immutable_slot=?3").map_err(unavailable)?;
    let rows = q
        .query_map(params![profile.record.reference, stream, slot], |r| {
            r.get::<_, String>(0)
        })
        .map_err(unavailable)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(unavailable)?;
    if rows.len() != 1 {
        return Err(TransportError::Authentication);
    }
    Ok(rows[0].clone())
}
fn require_assertion_original(
    assertion: &ReceivedNamedVerifierAssertion,
    original: &NamedRecipientOriginalRecordV1,
) -> ImportResult<()> {
    if assertion.inspection().package_digest() != original.assertion_package_digest
        || assertion.inspection().own().inspection().artifact_digest()
            != original.canonical_artifact_digest
        || assertion.inspection().own().inspection().policy_digest() != original.own_policy_digest
    {
        return Err(TransportError::WrongContext);
    }
    Ok(())
}
// Sequence is reserved by immutable Started, not by an uncertain result.
// Concurrent reviews cannot commit the same per-stream sequence; stale reviews
// fail before key use and exact ciphertext recovery never resequences.
pub(super) fn next_return_sequence(
    c: &rusqlite::Connection,
    original: &NamedRecipientOriginalRecordV1,
) -> ImportResult<u64> {
    let mut q = c.prepare("SELECT o.payload,s.payload,r.payload FROM signer_named_recipient_originals o JOIN signer_named_recipient_started s ON s.original_ref=o.reference LEFT JOIN signer_named_recipient_results r ON r.authorization_id=s.authorization_id WHERE o.profile_ref=?1").map_err(unavailable)?;
    let rows = q
        .query_map([&original.profile_ref], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(unavailable)?;
    let mut maximum = 0;
    for row in rows {
        let (o, s, result) = row.map_err(unavailable)?;
        let prior: NamedRecipientOriginalRecordV1 = decode(o).map_err(unavailable)?;
        if prior.terms.network_profile_id != original.terms.network_profile_id
            || prior.terms.agreement_id != original.terms.agreement_id
        {
            continue;
        }
        // An unresolved Started has consumed its immutable sequence but cannot
        // deliver ciphertext. Fence this stream rather than create an unrecoverable
        // replay gap or resequence any historical return. Other streams are separate.
        let result = result.ok_or(TransportError::ImportCommittedButUnavailable)?;
        let started: NamedRecipientStartedRecordV1 = decode(s).map_err(unavailable)?;
        let result: NamedRecipientResultRecordV1 = decode(result).map_err(unavailable)?;
        result.validate(&started, &prior).map_err(unavailable)?;
        let review = started
            .final_review
            .ok_or(TransportError::AuthorityUnavailable)?;
        maximum = maximum.max(review.return_sequence);
    }
    maximum
        .checked_add(1)
        .filter(|s| *s <= i64::MAX as u64)
        .ok_or(TransportError::ResourceLimit)
}
fn commit_started(
    journal: &SignerConsentJournal,
    profile: &LiveNamedRecipientProfile,
    original: &NamedRecipientOriginalRecordV1,
    started: &NamedRecipientStartedRecordV1,
    check: &impl Fn() -> ImportResult<()>,
) -> ImportResult<()> {
    let mut c = journal.connection.lock().map_err(unavailable)?;
    let tx = c
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(unavailable)?;
    require_unstarted_connection(&tx, &started.authorization_id)?;
    let raw: String = tx
        .query_row(
            "SELECT payload FROM signer_named_recipient_originals WHERE reference=?1",
            [&original.reference],
            |r| r.get(0),
        )
        .map_err(unavailable)?;
    if decode::<NamedRecipientOriginalRecordV1>(raw).map_err(unavailable)? != *original {
        return Err(TransportError::WrongContext);
    }
    super::super::super::named_recipient_inventory::read_all(&tx, &profile.record.account_id)
        .map_err(unavailable)?;
    started.validate(original).map_err(unavailable)?;
    if started
        .final_review
        .as_ref()
        .ok_or(TransportError::AuthorityUnavailable)?
        .return_sequence
        != next_return_sequence(&tx, original)?
    {
        return Err(TransportError::WrongContext);
    }
    let raw = encode(started).map_err(unavailable)?;
    tx.execute(
        "INSERT INTO signer_named_recipient_started VALUES(?1,?2,?3,?4)",
        params![
            started.authorization_id,
            started.original_ref,
            started.marker_digest().map_err(unavailable)?,
            raw.as_str()
        ],
    )
    .map_err(unavailable)?;
    storage::bounded(&tx, journal.capacity_limits()).map_err(unavailable)?;
    check()?;
    let _publication = profile.source.publication_lease().map_err(unavailable)?;
    check()?;
    tx.commit()
        .map_err(|_| TransportError::ImportCommittedButUnavailable)?;
    check().map_err(|_| TransportError::ImportCommittedButUnavailable)
}
fn commit_result(
    journal: &SignerConsentJournal,
    profile: &LiveNamedRecipientProfile,
    started: &NamedRecipientStartedRecordV1,
    result: &NamedRecipientResultRecordV1,
    check: &impl Fn() -> ImportResult<()>,
) -> ImportResult<()> {
    let mut c = journal.connection.lock().map_err(unavailable)?;
    let tx = c
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(unavailable)?;
    let raw: String = tx
        .query_row(
            "SELECT payload FROM signer_named_recipient_started WHERE authorization_id=?1",
            [&started.authorization_id],
            |r| r.get(0),
        )
        .map_err(unavailable)?;
    if decode::<NamedRecipientStartedRecordV1>(raw).map_err(unavailable)? != *started {
        return Err(TransportError::WrongContext);
    }
    let original_raw: String = tx
        .query_row(
            "SELECT payload FROM signer_named_recipient_originals WHERE reference=?1",
            [&started.original_ref],
            |r| r.get(0),
        )
        .map_err(unavailable)?;
    let original: NamedRecipientOriginalRecordV1 = decode(original_raw).map_err(unavailable)?;
    result.validate(started, &original).map_err(unavailable)?;
    let payload = encode(result).map_err(unavailable)?;
    tx.execute(
        "INSERT INTO signer_named_recipient_results VALUES(?1,?2,?3)",
        params![
            result.authorization_id,
            result.result_digest,
            payload.as_str()
        ],
    )
    .map_err(unavailable)?;
    super::super::super::named_recipient_inventory::read_all(&tx, &profile.record.account_id)
        .map_err(unavailable)?;
    storage::bounded(&tx, journal.capacity_limits()).map_err(unavailable)?;
    check()?;
    let _publication = profile.source.publication_lease().map_err(unavailable)?;
    check()?;
    tx.commit().map_err(unavailable)?;
    check()
}
fn seal_signature_return(
    profile: &LiveNamedRecipientProfile,
    original: &NamedRecipientOriginalRecordV1,
    started: &NamedRecipientStartedRecordV1,
    bytes: &[u8],
) -> ImportResult<(String, wire::EncryptedEnvelope)> {
    let review = started
        .final_review
        .as_ref()
        .ok_or(TransportError::AuthorityUnavailable)?;
    let t = &original.terms;
    let raw = super::super::super::named_recipient_records::signature_return_projection(
        original, started, bytes,
    )
    .map_err(unavailable)?;
    let projection = hex::encode(Sha256::digest(&*raw));
    let sender =
        wire::TransportSecret::from_bytes(profile.record.transport_secret).map_err(unavailable)?;
    let recipient =
        wire::TransportPublicKey::from_bytes(profile.record.return_transport_public_key)
            .map_err(unavailable)?;
    let now =
        wire::Timestamp::from_unix_seconds(i64::try_from(wall_ms()? / 1000).map_err(unavailable)?)
            .map_err(unavailable)?;
    let prepared=wire::prepare_export(wire::ExportRequest{context:wire::MessageContext{network_profile_id:t.network_profile_id.clone(),agreement_id:t.agreement_id.clone(),proposal_id:t.proposal_id.clone(),proposal_revision:t.proposal_revision,sender_id:format!("offline-return:{}",t.offline_signer_key_digest),recipient_id:format!("offline-return:{}",t.return_recipient_key_digest),artifact_kind:wire::ArtifactKind::OfflineAuthorizationReturn},order:wire::MessageOrder{message_id:review.return_message_id.clone(),sequence:review.return_sequence,issued_at:wire::Timestamp::from_unix_seconds(review.return_issued_at).map_err(unavailable)?,expires_at:wire::Timestamp::from_unix_seconds(review.return_expires_at).map_err(unavailable)?},purpose:"Exact own signatures for the original named-mode authorization".into(),persistence_warning:"This encrypted return can outlive local revocation; online current validation remains required.".into()},vec![wire::DisclosureField::new("offline-authorization-return-v1",raw.to_vec()).map_err(unavailable)?],&sender.public_key().map_err(unavailable)?,&recipient,&now).map_err(unavailable)?;
    let approved = prepared.preview().digest().map_err(unavailable)?;
    let envelope =
        wire::seal_original_return(prepared, &sender, &approved, &now).map_err(unavailable)?;
    Ok((projection, envelope))
}
mod return_file;
pub(crate) use return_file::PreparedNamedRecipientReturnFile;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn named_started_without_result_never_permits_another_signing_attempt() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE signer_named_recipient_started(authorization_id TEXT); CREATE TABLE signer_named_recipient_results(authorization_id TEXT);").unwrap();
        require_unstarted_connection(&c, "original").unwrap();
        c.execute(
            "INSERT INTO signer_named_recipient_started VALUES(?1)",
            ["original"],
        )
        .unwrap();
        assert!(matches!(
            require_unstarted_connection(&c, "original"),
            Err(TransportError::ImportCommittedButUnavailable)
        ));
        require_unstarted_connection(&c, "another").unwrap();
        c.execute(
            "INSERT INTO signer_named_recipient_results VALUES(?1)",
            ["orphaned-result"],
        )
        .unwrap();
        assert!(require_unstarted_connection(&c, "orphaned-result").is_err());
    }
    #[test]
    fn operation_revocation_is_shared_and_its_original_deadline_never_renews() {
        let operation = NamedRecipientOperation::new();
        let clone = operation.clone();
        assert!(operation.check().is_ok());
        assert_eq!(operation.deadline, clone.deadline);
        clone.revoke();
        assert!(operation.check().is_err());
        assert!(clone.check().is_err());
        let expired = NamedRecipientOperation {
            cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            deadline: Instant::now(),
        };
        assert!(expired.check().is_err());
        assert!(expired.clone().check().is_err());
    }
}
