//! Strict mixed historical schema19 reader. Never a financial adapter.
use super::*;
use rusqlite::Connection;
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "profile", content = "intent", rename_all = "snake_case")]
pub(crate) enum HistoricalFinancialAdmissionIntent {
    V1(RetainedDurablePaymentAdmissionIntentV1),
    V2(RetainedDurableDeliveryAdmissionIntentV2),
    #[cfg(all(feature = "durable-proposal", target_os = "linux"))]
    V3(RetainedDurableDeliveryAdmissionIntentV3),
    #[cfg(all(feature = "coordinated-financial-workflow-v1", target_os = "linux"))]
    CoordinatedV3(authority::durable_delivery_admission_intent_v3::coordinated_v1::RetainedCoordinatedAdmissionIntentV1),
}
// Read the explicit discriminator without a Value/untagged fallback. Serde
// refuses a duplicate version; the selected closed typed reader then validates
// every field, duplicate, canonical byte, index and original historical link.
#[derive(serde::Deserialize)]
struct Version { version: u16 }
fn version(payload: String) -> Result<u16> { Ok(decode::<Version>(payload)?.version) }
pub(crate) fn read_all(c: &Connection) -> Result<Vec<HistoricalFinancialAdmissionIntent>> {
    let mut q = c.prepare("SELECT authorization_id,payload FROM signer_durable_payment_admission_intents ORDER BY authorization_id LIMIT 100001")?;
    let rows = q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if rows.len() as u64 > MAX_BACKUP_ROWS { return Err(JournalError::Limit); }
    let versions = rows.iter().map(|(_, payload)| version(payload.clone())).collect::<Result<Vec<_>>>()?;
    require_separate_delivery_profile(&versions)?;
    rows.into_iter().map(|(id, payload)| match version(payload)? {
        1 => durable_payment_admission_intent_v1::read(c, &id)?.map(HistoricalFinancialAdmissionIntent::V1).ok_or(JournalError::NotFound),
        2 => durable_delivery_admission_intent_v2::read(c, &id)?.map(HistoricalFinancialAdmissionIntent::V2).ok_or(JournalError::NotFound),
        #[cfg(all(feature = "durable-proposal", target_os = "linux"))]
        3 => authority::durable_delivery_admission_intent_v3::read(c, &id)?.map(HistoricalFinancialAdmissionIntent::V3).ok_or(JournalError::NotFound),
        #[cfg(all(feature = "coordinated-financial-workflow-v1", target_os = "linux"))]
        4 => authority::durable_delivery_admission_intent_v3::coordinated_v1::read(c, &id)?.map(HistoricalFinancialAdmissionIntent::CoordinatedV3).ok_or(JournalError::NotFound),
        // Unsupported profiles never fall through into a different decoder.
        _ => Err(JournalError::RecoveryRequired),
    }).collect()
}
pub(crate) fn validate_rows(c: &Connection) -> Result<()> { read_all(c).map(|_| ()) }

/// Existing V1 issuer guard also denies V3; recognizing later history cannot
/// make it an empty/V1 financial namespace.
pub(crate) fn require_no_v2(c: &Connection) -> Result<()> {
    if read_all(c)?.iter().any(|intent| !matches!(intent, HistoricalFinancialAdmissionIntent::V1(_))) {
        return Err(JournalError::RecoveryRequired);
    }
    Ok(())
}
/// Deny-only V2 writer guard over the ENTIRE actual transaction, including a
/// V3 row with a different authorization ID. It never rewrites such history.
pub(crate) fn require_no_v3(c: &Connection) -> Result<()> {
    let mut q = c.prepare("SELECT payload FROM signer_durable_payment_admission_intents LIMIT 100001")?;
    let rows = q.query_map([], |r| r.get::<_, String>(0))?.collect::<std::result::Result<Vec<_>, _>>()?;
    if rows.len() as u64 > MAX_BACKUP_ROWS { return Err(JournalError::Limit); }
    for payload in rows {
        if !matches!(version(payload)?, 1 | 2) { return Err(JournalError::RecoveryRequired); }
    }
    Ok(())
}

// A namespace may contain old V1/V2 history together, but neither native nor
// coordinated V3 can be mixed with a different admission provenance profile.
fn require_separate_delivery_profile(versions: &[u16]) -> Result<()> {
    for exclusive in [3, 4] {
        if versions.contains(&exclusive) && versions.iter().any(|v| *v != exclusive) {
            return Err(JournalError::RecoveryRequired);
        }
    }
    Ok(())
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    #[test]
    fn native_and_coordinated_v3_never_mix_or_fall_back() {
        for profile in [3, 4] {
            for other in [1, 2, 3, 4, 5] {
                if profile != other {
                    assert!(require_separate_delivery_profile(&[profile, other]).is_err());
                    assert!(require_separate_delivery_profile(&[other, profile]).is_err());
                }
            }
            assert!(require_separate_delivery_profile(&[profile]).is_ok());
            assert!(require_separate_delivery_profile(&[profile, profile]).is_ok());
        }
        assert!(require_separate_delivery_profile(&[]).is_ok());
        assert!(require_separate_delivery_profile(&[1, 2]).is_ok());
    }

    #[test]
    fn discriminator_does_not_accept_duplicate_version() {
        assert!(version(r#"{"version":3,"version":4}"#.into()).is_err());
        assert_eq!(version(r#"{"version":4}"#.into()).unwrap(), 4);
    }
}
