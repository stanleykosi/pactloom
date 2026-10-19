//! Strict mixed historical schema19 reader. Never a v1 financial adapter.
use super::*;
use rusqlite::Connection;
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "profile", content = "intent", rename_all = "snake_case")]
pub(crate) enum HistoricalFinancialAdmissionIntent {
    V1(RetainedDurablePaymentAdmissionIntentV1),
    V2(RetainedDurableDeliveryAdmissionIntentV2),
}
pub(crate) fn read_all(c: &Connection) -> Result<Vec<HistoricalFinancialAdmissionIntent>> {
    let mut q = c.prepare("SELECT authorization_id FROM signer_durable_payment_admission_intents ORDER BY authorization_id LIMIT 100001")?;
    let ids = q
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if ids.len() as u64 > MAX_BACKUP_ROWS {
        return Err(JournalError::Limit);
    }
    ids.into_iter()
        .map(|id| {
            // Each attempt parses directly into its closed typed structure, checks
            // canonical bytes, every index and the original enrollment/manifest FKs.
            // No serde Value or untagged buffering can discard duplicate keys.
            if let Ok(Some(intent)) = durable_payment_admission_intent_v1::read(c, &id) {
                return Ok(HistoricalFinancialAdmissionIntent::V1(intent));
            }
            durable_delivery_admission_intent_v2::read(c, &id)?
                .map(HistoricalFinancialAdmissionIntent::V2)
                .ok_or(JournalError::NotFound)
        })
        .collect()
}
pub(crate) fn validate_rows(c: &Connection) -> Result<()> {
    read_all(c).map(|_| ())
}

/// Deny-only guard for old financial issuers, in their actual transaction.
/// Recognizing v2 history never makes it an empty/v1 financial namespace.
pub(crate) fn require_no_v2(c: &Connection) -> Result<()> {
    if read_all(c)?
        .iter()
        .any(|intent| matches!(intent, HistoricalFinancialAdmissionIntent::V2(_)))
    {
        return Err(JournalError::RecoveryRequired);
    }
    Ok(())
}
