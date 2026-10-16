//! Separately approved disclosure of an exact retained finalized transaction.
//! Never exports PCZT, viewing keys, signatures journals or writer authority.
use super::*;

pub struct TransactionDisclosureScope<'a> {
    pub retention: &'a TransactionRetentionScope,
    pub transaction_digest: &'a str,
    pub transaction_id: &'a str,
    pub recipient_id: &'a str,
    pub purpose: &'a str,
}
/// Implementations must hold current native disclosure authority through the
/// callback. Retention, signing and submission permissions are insufficient.
pub trait TransactionDisclosureConsent {
    fn permits(&self, scope: &TransactionDisclosureScope<'_>) -> bool;
}
impl SignedResultJournal {
    /// The callback must invoke the supplied current-permission check after any
    /// interactive wait and before its final disclosure effect.
    #[allow(clippy::too_many_arguments)]
    pub fn disclose_retained_transaction<R>(
        &self,
        context: SignedCandidateContext,
        key: &str,
        base: &[u8],
        policy: &ReviewPolicy,
        signatures: &[ExternalSignature],
        limits: ProvingLimits,
        signed_consent: &dyn SignedRetentionConsent,
        local: LocalTransactionCheckpoint<'_>,
        recipient_id: &str,
        purpose: &str,
        consent: &dyn TransactionDisclosureConsent,
        disclose: impl FnOnce(&[u8], &dyn Fn() -> Result<()>) -> R,
    ) -> Result<R> {
        if recipient_id.is_empty()
            || recipient_id.len() > 256
            || purpose.is_empty()
            || purpose.len() > 1024
        {
            return Err(RetentionError::InvalidRequest);
        }
        let (scope, signed) = self.verified_transaction_predecessor(
            context,
            key,
            base,
            policy,
            signatures,
            limits,
            signed_consent,
        )?;
        let gatekeeper = CombinedRetentionGate {
            signed: signed_consent,
            transaction: local.consent,
        };
        gate(&gatekeeper, &scope)?;
        let encoded =
            Zeroizing::new(serde_json::to_vec(&scope).map_err(|_| RetentionError::InvalidRequest)?);
        let request = framed(&[b"transaction-checkpoint-v1", &encoded]);
        let checkpoint = format!(
            "transaction-{}",
            framed(&[b"transaction-id-v1", scope.signed_result_id.as_bytes()])
        );
        let existing = {
            let c = local
                .journal
                .connection
                .lock()
                .map_err(|_| RetentionError::Storage)?;
            recovery::read_existing(&c, &checkpoint, &request, &encoded)?
                .ok_or(RetentionError::RecoveryRequired)?
        };
        recovery::verify_original(&existing, &signed, policy)?;
        let disclosure = TransactionDisclosureScope {
            retention: &scope,
            transaction_digest: &existing.digest,
            transaction_id: &existing.txid,
            recipient_id,
            purpose,
        };
        if !consent.permits(&disclosure) {
            return Err(RetentionError::ConsentDenied);
        }
        gate(&gatekeeper, &scope)?;
        let current = || {
            gate(&gatekeeper, &scope)?;
            if !consent.permits(&disclosure) {
                return Err(RetentionError::ConsentDenied);
            }
            Ok(())
        };
        let result = disclose(&existing.bytes, &current);
        gate(&gatekeeper, &scope)?;
        if !consent.permits(&disclosure) {
            return Err(RetentionError::ConsentDenied);
        }
        Ok(result)
    }
}
