//! Pure wallet-review utilities only. These functions create no permission,
//! source handle, wallet, provider connection, controller or key-use ticket.
use super::*;

/// Retain the exact originally reviewed JSON, not a subsequently reparsed file.
/// The digest binds the complete bytes (including harmless formatting changes).
pub(super) fn configuration_digest(json: &str) -> Result<String> {
    let _ = Config::parse_exact(json)?;
    wholepact_financial_coordinator_origin::SignerWalletOriginalV1::calculate_configuration_digest(
        json,
    )
    .map_err(|_| Error::InvalidData)
}

/// A sync duration is derived immediately before entry from already captured
/// absolute bounds. It is never a new 120 second action. The eventual nominal
/// caller must ALSO timeout_at the returned absolute deadline and resample its
/// actual action in LocalWalletAccess; this helper alone authorizes nothing.
pub(super) fn remaining_sync_budget(
    now: Instant,
    original_action: Instant,
    original_source: Instant,
    original_service: Instant,
    original_writer_session: Instant,
) -> Result<(Instant, Duration)> {
    let deadline = original_action
        .min(original_source)
        .min(original_service)
        .min(original_writer_session);
    let remaining = deadline
        .checked_duration_since(now)
        .filter(|d| !d.is_zero())
        .ok_or(Error::Locked)?;
    // All four inputs are original bounds; do not replace an excessive action
    // bound with now+120s, which would hide a broken nominal issuer contract.
    if remaining > Duration::from_secs(120) {
        return Err(Error::ReviewMismatch);
    }
    Ok((deadline, remaining))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sync_budget_never_renews_original_bounds() {
        let start = Instant::now();
        let at = |s| start + Duration::from_secs(s);
        assert_eq!(
            remaining_sync_budget(at(30), at(90), at(100), at(110), at(120)).unwrap(),
            (at(90), Duration::from_secs(60))
        );
        assert_eq!(
            remaining_sync_budget(at(80), at(90), at(100), at(110), at(120))
                .unwrap()
                .1,
            Duration::from_secs(10)
        );
        for bounds in [
            [90, 100, 110, 120],
            [120, 90, 110, 100],
            [120, 110, 90, 100],
            [120, 110, 100, 90],
        ] {
            assert!(remaining_sync_budget(
                at(90),
                at(bounds[0]),
                at(bounds[1]),
                at(bounds[2]),
                at(bounds[3])
            )
            .is_err());
        }
        assert!(remaining_sync_budget(start, at(121), at(200), at(200), at(200)).is_err());
    }
    #[test]
    fn config_rejects_empty_oversized_and_wrong_purpose_before_any_source_read() {
        assert!(configuration_digest("").is_err());
        assert!(configuration_digest(&" ".repeat(MAX_SETUP + 1)).is_err());
        assert!(configuration_digest(r#"{"schema_version":1,"purpose":"sign"}"#).is_err());
    }
    fn ordinary_config() -> serde_json::Value {
        serde_json::json!({"schema_version":1,"purpose":"fresh_born_ephemeral_viewing_wallet_v1","retention":"current_native_owner_only","maximum_blocks":10,
            "policy":{"confidence":"trusted_single_provider_snapshot","source_id":"ordinary-config-only","endpoint":"https://invalid.example","maximum_observation_age_seconds":30,"minimum_confirmations":2,"minimum_expiry_margin_blocks":3},
            "birthday":{"prior_height":1,"prior_block_hash":"00","sapling_tree":"","orchard_tree":"","ironwood_tree":""}})
    }
    #[test]
    fn config_digest_binds_exact_retained_bytes_not_reparsed_equivalence() {
        let json = serde_json::to_string(&ordinary_config()).unwrap();
        let spaced = format!(" {json} ");
        assert_eq!(
            configuration_digest(&json).unwrap(),
            configuration_digest(&json).unwrap()
        );
        assert_ne!(
            configuration_digest(&json).unwrap(),
            configuration_digest(&spaced).unwrap()
        );
    }
    #[test]
    fn config_never_accepts_synthetic_or_consensus_claims_and_unknown_fields() {
        for confidence in [
            "synthetic_never_chain_evidence",
            "independently_verified_consensus",
        ] {
            let mut value = ordinary_config();
            value["policy"]["confidence"] = confidence.into();
            assert!(configuration_digest(&serde_json::to_string(&value).unwrap()).is_err());
        }
        let mut value = ordinary_config();
        value["caller_permission"] = true.into();
        assert!(configuration_digest(&serde_json::to_string(&value).unwrap()).is_err());
    }
}
