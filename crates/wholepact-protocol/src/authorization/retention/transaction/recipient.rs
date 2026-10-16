//! Recipient-controlled incoming-key decryption of the original canonical saved
//! Ironwood transaction. This is private local evidence, not a transferable proof,
//! recipient identity issuer, scan integration, consensus claim or payment action.
use super::*;
use orchard::{keys::FullViewingKey, note_encryption::IronwoodDomain};
use std::fmt;
use zcash_note_encryption::try_note_decryption;
use zcash_protocol::memo::MemoBytes;

pub const RECIPIENT_VERIFIER_ID: &str = "maintained-ironwood-recipient-decryption-v1";
pub const RECIPIENT_FORMAT_ID: &str = "ironwood-v6-retained-transaction-viewing-key-v1";
const MAX_MONEY: u64 = 2_100_000_000_000_000;

#[derive(Debug)]
pub enum RecipientObservationError {
    Retention(RetentionError),
    InvalidRequest,
    ConsentDenied,
    RecipientKeyMismatch,
    RecipientAmountMismatch,
    RecipientMemoMismatch,
}
impl From<RetentionError> for RecipientObservationError {
    fn from(error: RetentionError) -> Self {
        Self::Retention(error)
    }
}
type RecipientResult<T> = std::result::Result<T, RecipientObservationError>;

/// Plain intended facts, not evidence or a source permission. A trusted engine
/// derives these from the immutable accepted recipient instruction and exact
/// transaction selection. No key, proof or raw memo appears in serialized APIs.
pub struct RecipientPaymentTarget<'a> {
    /// Authenticated current recipient caller, not the original retaining operator.
    pub principal_id: &'a str,
    pub profile_id: &'a str,
    pub recipient_id: &'a str,
    pub recipient_account_ref: &'a str,
    pub network_profile_id: &'a str,
    pub destination: &'a str,
    pub expected_amount_zatoshis: u64,
    pub expected_memo: Option<&'a str>,
    pub transaction_id: &'a str,
    pub transaction_digest: &'a str,
    pub effects_commitment: &'a str,
    pub privacy_purpose: &'a str,
}
/// Exact native permission scope for the recipient's viewing material. The
/// original journal object is supplied separately to the issuer for exact runtime
/// binding; labels and cryptographic fingerprints alone confer no authority.
#[derive(Clone, PartialEq, Eq)]
pub struct RecipientViewingScope {
    pub principal_id: String,
    pub retained_operator_principal_id: String,
    pub profile_id: String,
    pub recipient_id: String,
    pub recipient_account_ref: String,
    pub candidate_id: String,
    pub retained_checkpoint_id: String,
    pub transaction_id: String,
    pub transaction_digest: String,
    pub effects_commitment: String,
    pub network_profile_id: String,
    pub destination: String,
    pub expected_amount_zatoshis: u64,
    pub expected_memo_digest: String,
    pub privacy_purpose: String,
}
impl fmt::Debug for RecipientViewingScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecipientViewingScope { private_binding: [REDACTED] }")
    }
}
/// The source authenticates the independently enrolled recipient account and
/// privacy consent. It must keep the exact permission current while this guard
/// lives. Payment approval or access to contributor records does not grant it.
pub trait RecipientViewingKeyLease {
    fn scope(&self) -> &RecipientViewingScope;
    fn viewing_key(&self) -> &FullViewingKey;
    fn expires_at_unix_seconds(&self) -> u64;
    fn check_current(&self) -> RecipientResult<()>;
}
pub trait RecipientViewingKeySource {
    fn acquire<'a>(
        &'a self,
        scope: &RecipientViewingScope,
        exact_journal: &TransactionCheckpointJournal,
        now_unix_seconds: u64,
    ) -> RecipientResult<Box<dyn RecipientViewingKeyLease + 'a>>;
}
pub struct LocalRecipientObservation<'a, 'target> {
    pub transactions: LocalTransactionCheckpoint<'a>,
    pub transaction_read_consent: &'a dyn TransactionRecoveryConsent,
    pub recipient_viewing: &'a dyn RecipientViewingKeySource,
    pub target: RecipientPaymentTarget<'target>,
    pub now_unix_seconds: u64,
}

/// Actual decrypted output projection. No note randomness, private memo or key.
pub struct VerifiedRecipientOutput {
    output_ref: String,
    destination: String,
    amount_zatoshis: u64,
}
impl VerifiedRecipientOutput {
    pub fn output_ref(&self) -> &str {
        &self.output_ref
    }
    pub fn destination(&self) -> &str {
        &self.destination
    }
    pub fn amount_zatoshis(&self) -> u64 {
        self.amount_zatoshis
    }
}
/// Sealed by canonical transaction/proof/signature verification and maintained
/// incoming-key decryption. Its guard stays held through the caller's final chain
/// check/read result. It does not establish chain inclusion or expose raw bytes.
pub struct VerifiedRecipientOutputs<'a> {
    scope: RecipientViewingScope,
    outputs: Vec<VerifiedRecipientOutput>,
    evidence_digest: String,
    signed_candidate_digest: String,
    lease: Box<dyn RecipientViewingKeyLease + 'a>,
}
impl fmt::Debug for VerifiedRecipientOutputs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedRecipientOutputs { private_outputs: [REDACTED] }")
    }
}
impl VerifiedRecipientOutputs<'_> {
    pub fn scope(&self) -> &RecipientViewingScope {
        &self.scope
    }
    pub fn outputs(&self) -> &[VerifiedRecipientOutput] {
        &self.outputs
    }
    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }
    pub fn signed_candidate_digest(&self) -> &str {
        &self.signed_candidate_digest
    }
    pub fn check_current(&self, now_unix_seconds: u64) -> RecipientResult<()> {
        check_recipient_lease(&*self.lease, &self.scope, now_unix_seconds)
    }
}

impl SignedResultJournal {
    /// Revalidates the protected original signed predecessor and saved exact
    /// transaction, then decrypts actual outputs with recipient-held viewing
    /// authority. No extraction, new intent, release, broadcast or proof is made.
    #[allow(clippy::too_many_arguments)]
    pub fn observe_retained_recipient_outputs<'a>(
        &self,
        context: SignedCandidateContext,
        idempotency_key: &str,
        base: &[u8],
        policy: &ReviewPolicy,
        signatures: &[ExternalSignature],
        limits: ProvingLimits,
        signed_consent: &dyn SignedRetentionConsent,
        local: LocalRecipientObservation<'a, '_>,
    ) -> RecipientResult<VerifiedRecipientOutputs<'a>> {
        let (retention_scope, signed) = self.verified_transaction_predecessor(
            context,
            idempotency_key,
            base,
            policy,
            signatures,
            limits,
            signed_consent,
        )?;
        let retention = CombinedRetentionGate {
            signed: signed_consent,
            transaction: local.transactions.consent,
        };
        let target = &local.target;
        validate_target(target, local.now_unix_seconds)?;
        let receiver = crate::review::decode_testnet_receiver(target.destination)
            .map_err(|_| RecipientObservationError::InvalidRequest)?;
        let memo = match target.expected_memo {
            Some(text) => MemoBytes::from_bytes(text.as_bytes())
                .map_err(|_| RecipientObservationError::InvalidRequest)?,
            None => MemoBytes::empty(),
        }
        .into_bytes();
        let review = crate::review::verify_review(&signed, policy)
            .map_err(|_| RetentionError::VerificationFailed)?;
        if review.shielded_sighash() != target.effects_commitment {
            return Err(RetentionError::VerificationFailed.into());
        }
        let scope_bytes = Zeroizing::new(
            serde_json::to_vec(&retention_scope)
                .map_err(|_| RecipientObservationError::InvalidRequest)?,
        );
        if scope_bytes.len() > 16384 {
            return Err(RecipientObservationError::InvalidRequest);
        }
        let request_digest = framed(&[b"transaction-checkpoint-v1", &scope_bytes]);
        let checkpoint_id = format!(
            "transaction-{}",
            framed(&[
                b"transaction-id-v1",
                retention_scope.signed_result_id.as_bytes()
            ])
        );
        let scope = RecipientViewingScope {
            principal_id: target.principal_id.into(),
            retained_operator_principal_id: retention_scope
                .signed_scope
                .context
                .principal_id
                .clone(),
            profile_id: target.profile_id.into(),
            recipient_id: target.recipient_id.into(),
            recipient_account_ref: target.recipient_account_ref.into(),
            candidate_id: retention_scope.signed_scope.context.candidate_id.clone(),
            retained_checkpoint_id: checkpoint_id.clone(),
            transaction_id: target.transaction_id.into(),
            transaction_digest: target.transaction_digest.into(),
            effects_commitment: target.effects_commitment.into(),
            network_profile_id: target.network_profile_id.into(),
            destination: target.destination.into(),
            expected_amount_zatoshis: target.expected_amount_zatoshis,
            expected_memo_digest: hash(&memo),
            privacy_purpose: target.privacy_purpose.into(),
        };
        let lease = local.recipient_viewing.acquire(
            &scope,
            local.transactions.journal,
            local.now_unix_seconds,
        )?;
        check_recipient_lease(&*lease, &scope, local.now_unix_seconds)?;
        let incoming_scope = lease
            .viewing_key()
            .scope_for_address(&receiver)
            .ok_or(RecipientObservationError::RecipientKeyMismatch)?;
        let incoming = lease.viewing_key().to_ivk(incoming_scope).prepare();
        inspect_gate(
            &retention,
            local.transaction_read_consent,
            &retention_scope,
            target,
        )?;
        let bytes = {
            let connection = local
                .transactions
                .journal
                .connection
                .lock()
                .map_err(|_| RetentionError::Storage)?;
            let intent: Option<(String, Vec<u8>)> = connection.query_row(
                "SELECT request_digest,scope FROM transaction_intents WHERE checkpoint_id=?1 AND length(scope)<=16384",
                [&checkpoint_id], |r| Ok((r.get(0)?, r.get(1)?)),
            ).optional().map_err(db)?;
            let (saved_request, saved_scope) = intent.ok_or(RetentionError::IntentNotFound)?;
            let saved_scope = Zeroizing::new(saved_scope);
            if saved_request != request_digest || saved_scope.as_slice() != scope_bytes.as_slice() {
                return Err(RetentionError::IdempotencyConflict.into());
            }
            let retained: Option<(Option<Vec<u8>>, String, String)> = connection.query_row(
                "SELECT CASE WHEN length(bytes)<=1048576 THEN bytes ELSE NULL END,substr(digest,1,65),substr(txid,1,65) FROM transaction_results WHERE checkpoint_id=?1",
                [&checkpoint_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            ).optional().map_err(db)?;
            let (bytes, digest, txid) = retained.ok_or(RetentionError::RecoveryRequired)?;
            let bytes = Zeroizing::new(bytes.ok_or(RetentionError::VerificationFailed)?);
            if digest != target.transaction_digest
                || txid != target.transaction_id
                || hash(&bytes) != digest
            {
                return Err(RetentionError::VerificationFailed.into());
            }
            bytes
        };
        if verify_saved_transaction(&bytes, &signed, policy)? != target.transaction_id {
            return Err(RetentionError::VerificationFailed.into());
        }
        // The preceding maintained verifier already rejected noncanonical bytes,
        // unsupported pools/versions, bad signatures/proofs and wrong effects.
        let pczt = Pczt::parse(&signed).map_err(|_| RetentionError::VerificationFailed)?;
        let branch = BranchId::try_from(*pczt.global().consensus_branch_id())
            .map_err(|_| RetentionError::VerificationFailed)?;
        let transaction = Transaction::read(&mut std::io::Cursor::new(bytes.as_slice()), branch)
            .map_err(|_| RetentionError::VerificationFailed)?;
        let bundle = transaction
            .ironwood_bundle()
            .ok_or(RetentionError::VerificationFailed)?;
        if bundle.actions().len() > 8 {
            return Err(RetentionError::ResourceExhausted.into());
        }
        let mut outputs = Vec::new();
        let mut total = 0_u64;
        let mut evidence = Sha256::new();
        evidence.update(b"wholepact.private-recipient-decryption.v1\0");
        for part in [
            target.transaction_id,
            target.transaction_digest,
            target.effects_commitment,
            target.destination,
            scope.expected_memo_digest.as_str(),
        ] {
            evidence.update((part.len() as u64).to_le_bytes());
            evidence.update(part.as_bytes());
        }
        for (index, action) in bundle.actions().iter().enumerate() {
            let domain = IronwoodDomain::for_action(action);
            if let Some((note, address, actual_memo)) =
                try_note_decryption(&domain, &incoming, action)
            {
                // The same viewing key may also see a distinct change address.
                // Count all and only outputs for the exact selected receiver.
                if address != receiver {
                    continue;
                }
                if actual_memo != memo {
                    return Err(RecipientObservationError::RecipientMemoMismatch);
                }
                let value = note.value().inner();
                if value == 0 {
                    return Err(RecipientObservationError::RecipientAmountMismatch);
                }
                total = total
                    .checked_add(value)
                    .filter(|v| *v <= MAX_MONEY)
                    .ok_or(RecipientObservationError::RecipientAmountMismatch)?;
                let output_ref =
                    format!("ironwood:{index}:{}", hex::encode(action.cmx().to_bytes()));
                evidence.update((output_ref.len() as u64).to_le_bytes());
                evidence.update(output_ref.as_bytes());
                evidence.update(value.to_le_bytes());
                outputs.push(VerifiedRecipientOutput {
                    output_ref,
                    destination: target.destination.into(),
                    amount_zatoshis: value,
                });
            }
        }
        if outputs.is_empty() || total != target.expected_amount_zatoshis {
            return Err(RecipientObservationError::RecipientAmountMismatch);
        }
        inspect_gate(
            &retention,
            local.transaction_read_consent,
            &retention_scope,
            target,
        )?;
        check_recipient_lease(&*lease, &scope, local.now_unix_seconds)?;
        Ok(VerifiedRecipientOutputs {
            scope,
            outputs,
            evidence_digest: hex::encode(evidence.finalize()),
            signed_candidate_digest: retention_scope.signed_candidate_digest,
            lease,
        })
    }
}
fn check_recipient_lease(
    lease: &dyn RecipientViewingKeyLease,
    expected: &RecipientViewingScope,
    now: u64,
) -> RecipientResult<()> {
    if lease.scope() != expected || lease.expires_at_unix_seconds() <= now {
        return Err(RecipientObservationError::ConsentDenied);
    }
    lease.check_current()
}
fn inspect_gate(
    retention: &dyn TransactionRetentionConsent,
    read: &dyn TransactionRecoveryConsent,
    scope: &TransactionRetentionScope,
    target: &RecipientPaymentTarget<'_>,
) -> RecipientResult<()> {
    gate(retention, scope)?;
    if !read.permits(&TransactionRecoveryScope {
        retention: scope,
        action: RecoveryAction::InspectExistingIntent,
        transaction_digest: Some(target.transaction_digest),
        txid: Some(target.transaction_id),
    }) {
        return Err(RecipientObservationError::ConsentDenied);
    }
    gate(retention, scope)?;
    Ok(())
}
fn validate_target(target: &RecipientPaymentTarget<'_>, now: u64) -> RecipientResult<()> {
    let identifier = |s: &str| {
        !s.is_empty()
            && s.len() <= 128
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
    };
    let digest = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if now == 0
        || target.network_profile_id != "ironwood-testnet-nu7-candidate"
        || ![
            target.principal_id,
            target.profile_id,
            target.recipient_id,
            target.recipient_account_ref,
        ]
        .into_iter()
        .all(identifier)
        || ![
            target.transaction_id,
            target.transaction_digest,
            target.effects_commitment,
        ]
        .into_iter()
        .all(digest)
        || target.expected_amount_zatoshis == 0
        || target.expected_amount_zatoshis > MAX_MONEY
        || target.privacy_purpose.trim().is_empty()
        || target.privacy_purpose.len() > 1024
        || target.privacy_purpose.chars().any(char::is_control)
    {
        return Err(RecipientObservationError::InvalidRequest);
    }
    Ok(())
}
