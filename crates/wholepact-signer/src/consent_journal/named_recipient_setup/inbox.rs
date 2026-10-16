//! Concrete evidence-only named inbox owner. The sole writer is private and is
//! constructed only while consuming an exact genuine native import decision.
//! Imports create no admission, permit, signing key, or independent mode. The
//! separately gated final_signing child requires new exact native consent.
use super::super::{
    named_recipient_records::{
        NamedRecipientOriginalRecordV1, NamedRecipientOutputPurposeV1,
        NamedRecipientOwnExpectationsV1,
    },
    preconstruction_lease::PreconstructionRecordLease,
};
use super::*;
use wholepact_offline_bridge::{
    NamedVerifierEnvelopeExpectation, NamedVerifierExpectedContext,
    NamedVerifierRetainedPackageBinding, ReceivedNamedVerifierAssertion,
    named_verifier_original_context_digest, open_named_verifier_assertion_bound,
};
use wholepact_protocol::own_effects::{OwnEffectsPolicy, OwnOutputPurpose};
use wholepact_transport::{
    ArtifactKind, AuthenticatedReceipt, EncryptedEnvelope, MAX_ENCRYPTED_INBOX_BYTES,
    MAX_FILE_BYTES, MAX_REPLAY_RECORDS, MAX_REPLAY_STREAMS, MessageContext,
    NAMED_REVIEW_DISCLOSURE_PROFILE_V1, NamedReviewBindingV1, ReplayLedger, Timestamp,
    TransportError,
};

type ImportResult<T> = std::result::Result<T, TransportError>;

mod recovery;

/// This cannot be parsed, cloned or constructed from an imported original. Its
/// record is loaded only through this owner's held journal/session lease.
struct RetainedNamedRecipientOriginal {
    record: NamedRecipientOriginalRecordV1,
    original_context_digest: String,
    header: NamedReviewBindingV1,
}

/// Exact local review, bound to the live profile, immutable original, independent
/// wallet expectations and ciphertext. Native approval is still required.
/// Contains private own-account viewing data; deliberately no Debug/Serialize.
pub(crate) struct PreparedNamedRecipientImport {
    // Privately reloaded exact row with the same genuine process-local bindings.
    // No public Clone, Deserialize or raw-profile authority constructor exists.
    profile: LiveNamedRecipientProfile,
    original: RetainedNamedRecipientOriginal,
    own_policy: OwnEffectsPolicy,
    envelope: EncryptedEnvelope,
    envelope_digest: String,
    created: Instant,
    digest: String,
    display: String,
}

impl LiveNamedRecipientProfile {
    /// The actual native wallet caller supplies its freshly independently derived
    /// own policy. No wire policy, peer viewing key, profile/original DTO or bool
    /// selects the verifier or creates a live profile through this entry.
    pub(crate) fn prepare_assertion_import(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        original_ref: &str,
        own_policy: OwnEffectsPolicy,
        envelope: EncryptedEnvelope,
    ) -> ImportResult<PreparedNamedRecipientImport> {
        require_profile_owner(self, journal)?;
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
        let (record, original) = load_profile_and_original(journal, self, original_ref)?;
        require_own_context(self, &original.record, &own_policy, vault, &records)?;
        let envelope_digest = envelope_commitment(envelope.as_bytes())?;
        let digest = digest(
            "wholepact:native-named-recipient-import-review:v1",
            &(
                &self.record.reference,
                &original.record.reference,
                &envelope_digest,
                &original.record.own_expectations,
                &original.record.own_policy_digest,
                &original.record.reservation_request,
                &original.record.reservation_request_digest,
                &original.record.admission_export_template,
                self.source.entry_digest(),
            ),
        )
        .map_err(|_| TransportError::Malformed)?;
        let display = format!(
            "IMPORT EXACT NAMED-VERIFIER EVIDENCE\nAccount: {}\nProfile: {}\nOriginal authorization: {}\nOriginal reference: {}\nSelected verifier signing key: {}\nSelected verifier transport key: {}\nExact encrypted file: {}\nOriginal review package: {}\nMaximum own debit: {} zatoshis\nOwn fee share: {} zatoshis\nOriginal assertion validity: {} to {} ms\nTransaction expiry height: {}\nYou rely on this named verifier for peer attribution. Your own retained effects are independently checked. This import is evidence only; it does not reserve funds, authorize a signature, establish current chain facts, or renew any deadline. Independent verification mode remains unavailable.",
            self.record.account_id,
            self.record.reference,
            original.record.terms.authorization_id,
            original.record.reference,
            hex::encode(self.record.verifier_signing_public_key),
            hex::encode(self.record.verifier_transport_public_key),
            envelope_digest,
            original.record.terms.review_package_digest,
            original.record.terms.maximum_debit_zatoshis,
            original.record.terms.fee_share_zatoshis,
            original.record.validity_not_before_ms,
            original.record.validity_expires_ms,
            original.record.terms.transaction_expiry_height,
        );
        records.check_current().map_err(unavailable)?;
        self.source.check_current().map_err(unavailable)?;
        Ok(PreparedNamedRecipientImport {
            profile: LiveNamedRecipientProfile {
                record,
                journal: self.journal.clone(),
                source: self.source.clone(),
            },
            original,
            own_policy,
            envelope,
            envelope_digest,
            created: Instant::now(),
            digest,
            display,
        })
    }
}

impl PreparedNamedRecipientImport {
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn display(&self) -> &str {
        &self.display
    }

    /// `now` is the owner's transport-time input, never a trusted witness clock.
    /// An uncertain commit is reported as ImportCommittedButUnavailable. Never
    /// repackage, increment sequence, or create a new original to retry it.
    pub(crate) fn approve(
        self,
        decision: NativeDecision,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        now: &Timestamp,
    ) -> ImportResult<ReceivedNamedVerifierAssertion> {
        require_profile_owner(&self.profile, journal)?;
        if decision.binding() != &self.profile.source
            || decision.reviewed_digest() != self.digest
            || envelope_commitment(self.envelope.as_bytes())? != self.envelope_digest
        {
            return Err(TransportError::WrongContext);
        }
        let expires = self
            .created
            .checked_add(Duration::from_secs(120))
            .ok_or(TransportError::InvalidTime)?
            .min(
                decision
                    .consumed_at()
                    .checked_add(Duration::from_secs(120))
                    .ok_or(TransportError::InvalidTime)?,
            );
        check_setup_current(&self.profile.source, expires).map_err(unavailable)?;
        // One lease holds source-associated session and journal read fences all
        // the way through receipt commit. Never recursively reacquire a lease.
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
        let retained = load_original(journal, &self.profile, &self.original.record.reference)?;
        if retained.record != self.original.record
            || retained.header != self.original.header
            || retained.original_context_digest != self.original.original_context_digest
        {
            return Err(TransportError::WrongContext);
        }
        require_own_context(
            &self.profile,
            &retained.record,
            &self.own_policy,
            vault,
            &records,
        )?;
        let terms = &retained.record.reservation_request.intent.terms;
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
            original_artifact_digest: &retained.record.original_artifact_digest,
            transformation_commitment: &retained.record.transformation_digest,
            manifest_digest: &terms.manifest_digest,
            original_context_digest: &retained.original_context_digest,
            original_request_digest: &retained.record.original_request_digest,
            validity_not_before_ms: retained.record.validity_not_before_ms,
            validity_expires_ms: retained.record.validity_expires_ms,
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
            package_digest: &retained.record.assertion_package_digest,
            canonical_artifact_digest: &retained.record.canonical_artifact_digest,
            assertion_digest: &retained.record.named_assertion_digest,
            own_policy_digest: &retained.record.own_policy_digest,
        };
        let recipient = TransportSecret::from_bytes(self.profile.record.transport_secret)?;
        let sender =
            TransportPublicKey::from_bytes(self.profile.record.verifier_transport_public_key)?;
        let current = || {
            records.check_current().map_err(unavailable)?;
            check_setup_current(&self.profile.source, expires).map_err(unavailable)
        };
        let mut ledger = NativeNamedRecipientInbox {
            journal,
            profile: &self.profile,
            records: &records,
            expires,
            envelope_digest: &self.envelope_digest,
        };
        // The bound bridge checks signature, own effects and every exact package
        // commitment before invoking this private ledger with an unforgeable receipt.
        open_named_verifier_assertion_bound(
            &self.envelope,
            &recipient,
            &sender,
            &expected,
            &exact,
            now,
            &mut ledger,
            current,
        )
    }
}

fn unavailable<E>(_: E) -> TransportError {
    TransportError::AuthorityUnavailable
}

fn require_profile_owner(
    profile: &LiveNamedRecipientProfile,
    journal: &SignerConsentJournal,
) -> ImportResult<()> {
    profile.source.check_current().map_err(unavailable)?;
    if profile.journal != journal.binding() {
        return Err(TransportError::AuthorityUnavailable);
    }
    profile
        .record
        .validate()
        .map_err(|_| TransportError::WrongContext)
}

/// Reload exact private records only from the immutable local tables. Whole
/// inventory validation rejects disconnected originals, foreign policy/account
/// association, aliases, malformed receipts and unsafe legacy omissions.
fn load_original(
    journal: &SignerConsentJournal,
    profile: &LiveNamedRecipientProfile,
    original_ref: &str,
) -> ImportResult<RetainedNamedRecipientOriginal> {
    load_profile_and_original(journal, profile, original_ref).map(|(_, original)| original)
}

// Ownership is derived only from the existing live profile and the exact
// privately reloaded row, never from an imported raw record or a trust flag.
fn load_profile_and_original(
    journal: &SignerConsentJournal,
    profile: &LiveNamedRecipientProfile,
    original_ref: &str,
) -> ImportResult<(
    NamedRecipientProfileRecordV1,
    RetainedNamedRecipientOriginal,
)> {
    hash(original_ref).map_err(|_| TransportError::WrongContext)?;
    let c = journal
        .connection
        .lock()
        .map_err(|_| TransportError::Storage)?;
    storage::bounded(&c, journal.capacity_limits()).map_err(|_| TransportError::ResourceLimit)?;
    super::super::named_recipient_inventory::read_all(&c, &profile.record.account_id)
        .map_err(|_| TransportError::WrongContext)?;
    let stored: Option<String> = c.query_row(
        "SELECT CASE WHEN length(payload)<=?2 THEN payload ELSE NULL END FROM signer_named_recipient_profiles WHERE reference=?1",
        params![profile.record.reference, MAX_RECORD_BYTES as i64], |r| r.get(0),
    ).optional().map_err(|_| TransportError::Storage)?.flatten();
    let stored: NamedRecipientProfileRecordV1 = decode(stored.ok_or(TransportError::WrongContext)?)
        .map_err(|_| TransportError::WrongContext)?;
    if stored != profile.record {
        return Err(TransportError::WrongContext);
    }
    let raw: Option<String> = c.query_row(
        "SELECT CASE WHEN length(payload)<=?3 THEN payload ELSE NULL END FROM signer_named_recipient_originals WHERE reference=?1 AND profile_ref=?2",
        params![original_ref, profile.record.reference, MAX_RECORD_BYTES as i64], |r| r.get(0),
    ).optional().map_err(|_| TransportError::Storage)?.flatten();
    let record: NamedRecipientOriginalRecordV1 = decode(raw.ok_or(TransportError::WrongContext)?)
        .map_err(|_| TransportError::WrongContext)?;
    if record.reference != original_ref {
        return Err(TransportError::WrongContext);
    }
    let (original_context_digest, header) = require_original_binding(profile, &record)?;
    Ok((
        stored,
        RetainedNamedRecipientOriginal {
            record,
            original_context_digest,
            header,
        },
    ))
}

/// Evidence validation shared only with the sibling first-original owner. This
/// accepts no receipt, commits no state and grants no native authority. The
/// proposed record still needs actual independent own-effects and pinned-package
/// authentication before any transactional owner may retain it.
pub(super) fn require_original_binding(
    profile: &LiveNamedRecipientProfile,
    record: &NamedRecipientOriginalRecordV1,
) -> ImportResult<(String, NamedReviewBindingV1)> {
    record
        .validate(&profile.record)
        .map_err(|_| TransportError::WrongContext)?;
    record
        .reservation_request
        .validate()
        .map_err(|_| TransportError::WrongContext)?;
    if record.reservation_request.intent.terms != record.terms
        || record
            .reservation_request
            .request_digest()
            .map_err(|_| TransportError::WrongContext)?
            != record.reservation_request_digest
    {
        return Err(TransportError::WrongContext);
    }
    let original_context_digest =
        named_verifier_original_context_digest(&record.reservation_request.intent.terms)?;
    // Use the single transport-owned header implementation. This is a digest
    // commitment to retained inputs, never a substitute for their provenance.
    let header = NamedReviewBindingV1 {
        schema_version: 1,
        disclosure_profile: NAMED_REVIEW_DISCLOSURE_PROFILE_V1.into(),
        owner_setup_digest: profile.record.original_setup_digest.clone(),
        assertion_package_digest: record.assertion_package_digest.clone(),
        original_context_digest: original_context_digest.clone(),
    };
    if header.review_package_digest()? != record.terms.review_package_digest {
        return Err(TransportError::WrongContext);
    }
    Ok((original_context_digest, header))
}

pub(super) fn require_own_context(
    profile: &LiveNamedRecipientProfile,
    original: &NamedRecipientOriginalRecordV1,
    policy: &OwnEffectsPolicy,
    vault: &AccountVault,
    records: &PreconstructionRecordLease<'_>,
) -> ImportResult<()> {
    records
        .require_native_origin(&profile.source)
        .map_err(unavailable)?;
    require_original_binding(profile, original)?;
    let fvk = vault.account().fvk().map_err(unavailable)?;
    if vault.account().recovery_required()
        || vault.account_id().map_err(unavailable)? != profile.record.account_id
        || policy.account_id != profile.record.account_id
        || policy.own_fvk.to_bytes() != fvk.to_bytes()
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
    let proposal = wholepact_core::Proposal::validate(records.manifest().proposal_input().clone())
        .map_err(|_| TransportError::WrongContext)?;
    let owner = proposal
        .manifest()
        .participants
        .iter()
        .find(|owner| {
            owner.account_id == profile.record.account_id
                && owner.participant_id == records.enrollment().participant_id()
        })
        .ok_or(TransportError::WrongContext)?;
    if policy.maximum_selected_net_debit_zatoshis != owner.maximum_net_debit.as_zatoshis()
        || policy.declared_fee_share_zatoshis != owner.fee_share.as_zatoshis()
        || proposal
            .accounting()
            .participant_net_debits
            .get(&owner.participant_id)
            .map(|amount| amount.as_zatoshis())
            != Some(policy.exact_selected_net_debit_zatoshis)
    {
        return Err(TransportError::WrongContext);
    }
    let privacy = &proposal.manifest().agreement.privacy_profile;
    if privacy.mode != wholepact_core::PrivacyMode::DeclaredOperator
        || !privacy.dedicated_accounts_required
        || !privacy
            .proving_operator
            .as_deref()
            .is_some_and(|p| !p.trim().is_empty())
    {
        return Err(TransportError::AuthorityUnavailable);
    }
    require_exact_own_expectations(&original.own_expectations, policy)?;
    records.check_current().map_err(unavailable)?;
    profile.source.check_current().map_err(unavailable)
}

/// Compare every policy expectation; the cryptographic digest is independently
/// checked by the full bridge inspection before receipt acceptance. Do not copy
/// or weaken the maintained protocol's private policy-fingerprint algorithm.
fn require_exact_own_expectations(
    expected: &NamedRecipientOwnExpectationsV1,
    policy: &OwnEffectsPolicy,
) -> ImportResult<()> {
    if expected.full_viewing_key_digest != hex::encode(Sha256::digest(policy.own_fvk.to_bytes()))
        || expected.manifest_digest != hex::encode(policy.manifest_digest)
        || expected.anchor != hex::encode(policy.anchor)
        || expected.expiry_height != policy.expiry_height
        || expected.maximum_selected_net_debit_zatoshis
            != policy.maximum_selected_net_debit_zatoshis
        || expected.exact_selected_net_debit_zatoshis != policy.exact_selected_net_debit_zatoshis
        || expected.declared_fee_share_zatoshis != policy.declared_fee_share_zatoshis
        || expected.exact_transaction_fee_zatoshis != policy.exact_transaction_fee_zatoshis
        || expected.own_inputs.len() != policy.own_inputs.len()
        || expected.outputs.len() != policy.outputs.len()
    {
        return Err(TransportError::WrongContext);
    }
    for (a, b) in expected.own_inputs.iter().zip(&policy.own_inputs) {
        if usize::try_from(a.action_index).ok() != Some(b.action_index)
            || a.nullifier != hex::encode(b.nullifier)
            || a.value_zatoshis != b.value_zatoshis
        {
            return Err(TransportError::WrongContext);
        }
    }
    for (a, b) in expected.outputs.iter().zip(&policy.outputs) {
        let same_purpose = matches!(
            (a.purpose, b.purpose),
            (
                NamedRecipientOutputPurposeV1::OwnReturn,
                OwnOutputPurpose::OwnReturn
            ) | (
                NamedRecipientOutputPurposeV1::Recipient,
                OwnOutputPurpose::Recipient
            ) | (
                NamedRecipientOutputPurposeV1::PeerReturnUnverified,
                OwnOutputPurpose::PeerReturnUnverified
            )
        );
        if usize::try_from(a.action_index).ok() != Some(b.action_index)
            || a.receiver_hex != hex::encode(b.receiver.to_raw_address_bytes())
            || a.value_zatoshis != b.value_zatoshis
            || a.memo_hex != hex::encode(b.memo)
            || !same_purpose
        {
            return Err(TransportError::WrongContext);
        }
    }
    Ok(())
}

pub(super) fn envelope_commitment(bytes: &[u8]) -> ImportResult<String> {
    if bytes.is_empty() || bytes.len() > MAX_FILE_BYTES {
        return Err(TransportError::ResourceLimit);
    }
    Ok(super::super::named_recipient_records::domain_digest(
        b"wholepact.encrypted-envelope.v1\0",
        bytes,
    ))
}

// No visibility modifier and no standalone constructor. Possession of a parsed
// profile, receipt DTO or original JSON cannot instantiate this writer.
struct NativeNamedRecipientInbox<'a, 'lease> {
    journal: &'a SignerConsentJournal,
    profile: &'a LiveNamedRecipientProfile,
    records: &'a PreconstructionRecordLease<'lease>,
    expires: Instant,
    envelope_digest: &'a str,
}
impl NativeNamedRecipientInbox<'_, '_> {
    fn check_current(&self) -> ImportResult<()> {
        self.records.check_current().map_err(unavailable)?;
        check_setup_current(&self.profile.source, self.expires).map_err(unavailable)
    }
}
impl ReplayLedger for NativeNamedRecipientInbox<'_, '_> {
    fn accept_authenticated(
        &mut self,
        receipt: &AuthenticatedReceipt,
        envelope: &[u8],
    ) -> ImportResult<()> {
        self.check_current()?;
        let actual = envelope_commitment(envelope)?;
        if actual != self.envelope_digest || actual != receipt.envelope_digest() {
            return Err(TransportError::WrongContext);
        }
        let sequence = i64::try_from(receipt.sequence()).map_err(|_| TransportError::Malformed)?;
        if sequence < 1 {
            return Err(TransportError::Malformed);
        }
        let mut c = self
            .journal
            .connection
            .lock()
            .map_err(|_| TransportError::Storage)?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| TransportError::Storage)?;
        insert_authenticated(&tx, &self.profile.record.reference, receipt, envelope)?;
        storage::bounded(&tx, self.journal.capacity_limits())
            .map_err(|_| TransportError::ResourceLimit)?;
        self.records.check_current().map_err(unavailable)?;
        let publication = self
            .profile
            .source
            .publication_lease()
            .map_err(unavailable)?;
        self.check_current()?;
        // Once commit is attempted its success may be unknowable. Both a failed
        // commit acknowledgment and late loss preserve the exact recovery target.
        tx.commit()
            .map_err(|_| TransportError::ImportCommittedButUnavailable)?;
        self.check_current()
            .map_err(|_| TransportError::ImportCommittedButUnavailable)?;
        drop(publication);
        Ok(())
    }
}

fn insert_authenticated(
    tx: &rusqlite::Transaction<'_>,
    profile: &str,
    receipt: &AuthenticatedReceipt,
    envelope: &[u8],
) -> ImportResult<()> {
    // This helper remains private and only accepts an unforgeable authenticated
    // receipt. It is not an import-row adapter or a public privileged writer.
    let sequence = i64::try_from(receipt.sequence()).map_err(|_| TransportError::Malformed)?;
    if sequence < 1 || envelope_commitment(envelope)? != receipt.envelope_digest() {
        return Err(TransportError::Malformed);
    }
    let prior: Option<(String, String, i64)> = tx.query_row(
        "SELECT substr(content_hash,1,65),substr(message_id,1,65),sequence FROM signer_named_recipient_receipts WHERE profile_ref=?1 AND stream=?2 AND (sequence=?3 OR message_id=?4) LIMIT 1",
        params![profile, receipt.stream_digest(), sequence, receipt.message_id_digest()],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).optional().map_err(|_| TransportError::Storage)?;
    if let Some((content, message, old_sequence)) = prior {
        return Err(
            if content == receipt.content_digest()
                && message == receipt.message_id_digest()
                && old_sequence == sequence
            {
                TransportError::Replay
            } else {
                TransportError::Equivocation
            },
        );
    }
    if let Some(slot) = receipt.immutable_slot_digest() {
        let old: Option<String> = tx.query_row(
            "SELECT substr(payload_digest,1,65) FROM signer_named_recipient_receipts WHERE profile_ref=?1 AND immutable_slot=?2 LIMIT 1",
            params![profile,slot], |r| r.get(0),
        ).optional().map_err(|_| TransportError::Storage)?;
        if let Some(old) = old {
            return Err(if old == receipt.payload_digest() {
                TransportError::Replay
            } else {
                TransportError::Equivocation
            });
        }
    }
    let last: Option<i64> = tx.query_row(
        "SELECT max(sequence) FROM signer_named_recipient_receipts WHERE profile_ref=?1 AND stream=?2",
        params![profile,receipt.stream_digest()], |r| r.get(0),
    ).map_err(|_| TransportError::Storage)?;
    if last.unwrap_or(0).checked_add(1) != Some(sequence) {
        return Err(TransportError::OutOfOrder);
    }
    let (count, bytes): (i64, i64) = tx.query_row(
        "SELECT count(*),coalesce(sum(length(envelope_hex)/2),0) FROM signer_named_recipient_receipts",
        [], |r| Ok((r.get(0)?, r.get(1)?)),
    ).map_err(|_| TransportError::Storage)?;
    let streams: i64 = tx.query_row(
        "SELECT count(*) FROM (SELECT profile_ref,stream FROM signer_named_recipient_receipts GROUP BY profile_ref,stream)",
        [], |r| r.get(0),
    ).map_err(|_| TransportError::Storage)?;
    check_capacity(count, streams, bytes, last.is_none(), envelope.len())?;
    tx.execute(
        "INSERT INTO signer_named_recipient_receipts(profile_ref,stream,sequence,message_id,content_hash,payload_digest,envelope_digest,immutable_slot,envelope_hex) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![profile,receipt.stream_digest(),sequence,receipt.message_id_digest(),
            receipt.content_digest(),receipt.payload_digest(),receipt.envelope_digest(),
            receipt.immutable_slot_digest(),hex::encode(envelope)],
    ).map_err(|_| TransportError::Storage)?;
    Ok(())
}

fn check_capacity(
    count: i64,
    streams: i64,
    bytes: i64,
    new_stream: bool,
    incoming: usize,
) -> ImportResult<()> {
    if count < 0
        || streams < 0
        || bytes < 0
        || count >= MAX_REPLAY_RECORDS as i64
        || (new_stream && streams >= MAX_REPLAY_STREAMS as i64)
        || incoming > MAX_FILE_BYTES
        || bytes
            .checked_add(i64::try_from(incoming).map_err(|_| TransportError::ResourceLimit)?)
            .is_none_or(|n| n > MAX_ENCRYPTED_INBOX_BYTES as i64)
    {
        return Err(TransportError::ResourceLimit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_capacity_is_global_and_checked_without_arithmetic_wrap() {
        assert!(check_capacity(0, 0, 0, true, MAX_FILE_BYTES).is_ok());
        assert!(check_capacity(MAX_REPLAY_RECORDS as i64, 0, 0, false, 1).is_err());
        assert!(check_capacity(1, MAX_REPLAY_STREAMS as i64, 1, true, 1).is_err());
        assert!(check_capacity(1, MAX_REPLAY_STREAMS as i64, 1, false, 1).is_ok());
        assert!(check_capacity(1, 1, MAX_ENCRYPTED_INBOX_BYTES as i64, false, 1).is_err());
        assert!(check_capacity(1, 1, i64::MAX, false, 1).is_err());
        assert!(check_capacity(1, 1, 1, false, MAX_FILE_BYTES + 1).is_err());
        assert!(check_capacity(-1, 0, 0, true, 1).is_err());
    }
    #[test]
    fn ciphertext_binding_preserves_exact_bytes_and_rejects_empty_or_oversize() {
        let a = envelope_commitment(b"synthetic-ciphertext").unwrap();
        assert_ne!(a, envelope_commitment(b"synthetic-ciphertext ").unwrap());
        assert_eq!(
            a,
            super::super::super::named_recipient_records::domain_digest(
                b"wholepact.encrypted-envelope.v1\0",
                b"synthetic-ciphertext"
            )
        );
        assert!(envelope_commitment(&[]).is_err());
        assert!(envelope_commitment(&vec![0; MAX_FILE_BYTES + 1]).is_err());
    }
    #[test]
    fn final_predicate_retains_original_deadline_and_revoked_source_boundary() {
        let native = crate::native_ui::recovery_test_authority();
        let source = native.binding();
        let expires = Instant::now() + Duration::from_secs(60);
        assert!(check_setup_current(&source, expires).is_ok());
        assert!(check_setup_current(&source, Instant::now()).is_err());
        drop(native);
        assert!(check_setup_current(&source, expires).is_err());
    }
}

mod original_import;
pub(crate) use original_import::{
    NamedIntentExportTemplate, NamedRecipientOriginalInputs, PreparedNamedIntentFileExport,
    PreparedNamedRecipientOriginalImport, RetainedNamedIntentExport,
};

mod final_signing;
pub(crate) use final_signing::PreparedNamedRecipientReturnFile;
pub(crate) use final_signing::{NamedRecipientOperation, PreparedNamedRecipientSigning};

#[cfg(all(test, feature = "synthetic-qualification"))]
pub(super) fn next_return_sequence_for_test(
    c: &rusqlite::Connection,
    original: &NamedRecipientOriginalRecordV1,
) -> ImportResult<u64> {
    final_signing::next_return_sequence(c, original)
}
