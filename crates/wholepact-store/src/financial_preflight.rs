//! Read-only deny checks and retained local input exclusions. Not an admission
//! issuer, signer history source, account recovery or witness budget authority.
use crate::{authority::ReleaseIntent, *};
use std::collections::BTreeSet;

/// Exact local ledger snapshot only. Absence is not proof of complete external
/// history. No constructor, Deserialize or mutable access is exposed.
#[derive(PartialEq, Eq)]
pub struct RetainedInputExclusions {
    account_id: String,
    input_ids: BTreeSet<String>,
}
impl RetainedInputExclusions {
    /// Canonical commitment to this actual conservative local snapshot.
    /// The digest is inert; it cannot recreate a snapshot or remove exclusions.
    pub fn snapshot_digest(&self) -> Result<String> {
        request_digest(&serde_json::json!([
            "wholepact:retained-input-exclusions:v2",
            &self.account_id,
            &self.input_ids,
        ]))
    }
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn excludes(&self, local_input_id: &str, nullifier_hex: &str) -> bool {
        self.input_ids.contains(local_input_id) || self.input_ids.contains(nullifier_hex)
    }
}

impl Store {
    /// Checks actual authenticated Store state. This deliberately rejects EVERY
    /// recovered generation, even fresh labels, pending the distinct-authority
    /// issuer and immutable scope journal. No boolean can waive that boundary.
    pub fn require_ordinary_financial_lineage(
        &self,
        agreement: &str,
        obligation: &str,
        principal: &str,
        idempotency_key: Option<&str>,
        operation_ids: &[&str],
    ) -> Result<()> {
        validate_id(agreement)?;
        validate_id(obligation)?;
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        require_lineage_fences(
            self,
            &c,
            agreement,
            obligation,
            principal,
            idempotency_key,
            operation_ids,
        )?;
        if self.recovered_generation || crate::backup::read_recovery_state(&c)?.recovery_required {
            return Err(StoreError::RecoveryRequired);
        }
        let loss_fenced: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM records WHERE aggregate_type='settlement_applied' AND payload=?1)",
            [encode(&serde_json::json!(obligation))?], |r| r.get(0),
        )?;
        if loss_fenced {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(())
    }

    /// Conservative UNION of actual reservations and every retained release's
    /// inputs, including consumed and historically resolved entries. No release
    /// state is interpreted as permission to reuse an input here.
    pub fn retained_financial_input_exclusions(
        &self,
        account_id: &str,
    ) -> Result<RetainedInputExclusions> {
        validate_id(account_id)?;
        if self.protection != StorageProtection::Encrypted {
            return Err(StoreError::RecoveryRequired);
        }
        let mut connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        // Other ordinary Store connections may commit concurrently. Keep the
        // reservations and release-payload reads in one SQLite snapshot; this
        // is still only a local observation, never an atomic reservation.
        let c = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        // An opaque owner-authenticated recovered action issuer does not exist.
        // Do not return an apparently complete empty set from a recovered Store.
        if self.recovered_generation || crate::backup::read_recovery_state(&c)?.recovery_required {
            return Err(StoreError::RecoveryRequired);
        }
        read_retained_input_exclusions(&c, account_id, &BTreeSet::from([account_id.to_owned()]))
    }
}
// Individually testable restriction predicate. Success here is ONLY absence of
// the selected local fence; the public method always applies global denial next.
fn require_lineage_fences(
    store: &Store,
    c: &Connection,
    agreement: &str,
    obligation: &str,
    principal: &str,
    idempotency_key: Option<&str>,
    operation_ids: &[&str],
) -> Result<()> {
    if store.generation_fenced(c, "record", &format!("agreement:{agreement}"))?
        || store.generation_fenced(c, "obligation", obligation)?
    {
        return Err(StoreError::RecoveryRequired);
    }
    for operation in operation_ids {
        validate_id(operation)?;
        if store.generation_fenced(c, "operation", operation)?
            || store.generation_fenced(c, "effect", operation)?
        {
            return Err(StoreError::RecoveryRequired);
        }
    }
    if let Some(key) = idempotency_key {
        let context = CommandContext::for_request(principal, key, &serde_json::json!({}))?;
        store.require_current_replay(c, &context)?;
    }
    Ok(())
}

fn insert(ids: &mut BTreeSet<String>, input: String) -> Result<()> {
    // Native release input IDs are canonical protocol nullifier hex. The wallet
    // also exposes exact local ironwood:txid:index identities. Unknown formats
    // require an owning adapter; silently ignoring one would be unsafe.
    let hash = |v: &str| {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let local = input.split(':').collect::<Vec<_>>();
    let known_local = local.len() == 3
        && local[0] == "ironwood"
        && hash(local[1])
        && local[2]
            .parse::<u32>()
            .is_ok_and(|v| v.to_string() == local[2]);
    if !hash(&input) && !known_local {
        return Err(StoreError::RecoveryRequired);
    }
    ids.insert(input);
    if ids.len() > 100_000 {
        return Err(StoreError::ResourceExhausted);
    }
    Ok(())
}

/// Shared snapshot reader only. Callers retain their own concrete admission gates.
pub(crate) fn read_retained_input_exclusions(
    c: &Connection,
    account_id: &str,
    aliases: &BTreeSet<String>,
) -> Result<RetainedInputExclusions> {
    validate_id(account_id)?;
    if aliases.is_empty() || aliases.len() > 256 || !aliases.contains(account_id) {
        return Err(StoreError::RecoveryRequired);
    }
    let mut input_ids = BTreeSet::new();
    for alias in aliases {
        validate_id(alias)?;
        let mut q = c.prepare(
            "SELECT input_id FROM authority_reservations WHERE account_id=?1 ORDER BY input_id",
        )?;
        for row in q.query_map([alias], |r| r.get::<_, String>(0))? {
            insert(&mut input_ids, row?)?;
        }
        drop(q);
        let mut q = c.prepare("SELECT authorization_id,payload FROM authority_exposures WHERE account_id=?1 ORDER BY authorization_id")?;
        for row in q.query_map([alias], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })? {
            let (authorization, payload) = row?;
            let intent: ReleaseIntent = serde_json::from_str(&payload)?;
            crate::authority::validate_intent(&intent)?;
            if intent.account_id != *alias || intent.authorization_id != authorization {
                return Err(StoreError::RecoveryRequired);
            }
            for input in intent.input_ids {
                insert(&mut input_ids, input)?;
            }
        }
    }
    Ok(RetainedInputExclusions {
        account_id: account_id.into(),
        input_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::ExposureState;

    // Private raw fixture, following recovery.rs's in-memory fence fixtures.
    // Classification is changed solely to isolate read-only Store predicates.
    // This is NOT an encrypted opener, signer capability or admission fixture.
    fn modeled_protected_classification_store() -> Store {
        let mut store = Store::in_memory().unwrap();
        store.protection = StorageProtection::Encrypted;
        store
            .initialize_authority_account("synthetic-account", 1)
            .unwrap();
        store
    }
    fn release(id: &str, input: &str, amount: &str) -> ReleaseIntent {
        ReleaseIntent {
            authorization_id: id.into(),
            account_id: "synthetic-account".into(),
            writer_epoch: 1,
            obligation_id: format!("obligation-{id}"),
            proposal_id: format!("proposal-{id}"),
            manifest_digest: "a".repeat(64),
            effects_digest: "b".repeat(64),
            artifact_digest: "c".repeat(64),
            maximum_debit: amount.into(),
            input_ids: vec![input.into()],
            aggregate_budget_limit: "100".into(),
        }
    }
    // Manually modeled denial state only: never an actual protected successor
    // fixture, and never evidence that a generation opener accepted this Store.
    fn modeled_generation_denial_store() -> Store {
        let mut store = modeled_protected_classification_store();
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch(include_str!("recovery-schema.sql"))
            .unwrap();
        store.recovered_generation = true;
        store
    }
    fn add_fence(store: &Store, kind: &str, identity: &str) {
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO store_generation_fences VALUES(?1,?2,'synthetic-regression-only')",
                params![kind, identity],
            )
            .unwrap();
    }

    #[test]
    fn retained_union_keeps_consumed_uncertain_and_reservation_only_inputs_without_writes() {
        let store = modeled_protected_classification_store();
        let consumed = "1".repeat(64);
        let uncertain = "2".repeat(64);
        let reservation_only = "3".repeat(64);
        let expired = format!("ironwood:{}:7", "4".repeat(64));
        store
            .record_authorization_release_intent(&release("consumed", &consumed, "10"))
            .unwrap();
        store
            .record_observed_resolution("consumed", ExposureState::Consumed, "synthetic-consumed")
            .unwrap();
        store
            .record_authorization_release_intent(&release("uncertain", &uncertain, "20"))
            .unwrap();
        store
            .record_authorization_release_intent(&release("expired", &expired, "5"))
            .unwrap();
        store
            .record_observed_resolution(
                "expired",
                ExposureState::ExpiredObserved,
                "synthetic-expired",
            )
            .unwrap();
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO authority_reservations VALUES('synthetic-account',?1,'uncertain')",
                [&reservation_only],
            )
            .unwrap();
        let before = store.account_exposures("synthetic-account").unwrap();
        let exclusions = store
            .retained_financial_input_exclusions("synthetic-account")
            .unwrap();
        assert_eq!(exclusions.account_id(), "synthetic-account");
        assert_eq!(
            exclusions.input_ids,
            BTreeSet::from([
                consumed.clone(),
                uncertain.clone(),
                reservation_only.clone(),
                expired.clone()
            ])
        );
        assert!(exclusions.excludes("unrelated-local-id", &consumed));
        assert!(exclusions.excludes(&expired, &"f".repeat(64)));
        assert!(!exclusions.excludes("unrelated-local-id", &"f".repeat(64)));
        assert!(
            store
                .retained_financial_input_exclusions("other-account")
                .unwrap()
                .input_ids
                .is_empty()
        );
        assert_eq!(
            store.account_exposures("synthetic-account").unwrap(),
            before
        );
        assert_eq!(store.settled_debit("synthetic-account").unwrap(), "10");
        assert_eq!(store.outstanding_debit("synthetic-account").unwrap(), "25");
        let count: u64 = store
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM authority_reservations", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn unknown_or_noncanonical_retained_input_is_rejected_not_ignored() {
        for unknown in [
            "legacy-unmapped-input".to_string(),
            "A".repeat(64),
            format!("ironwood:{}:07", "1".repeat(64)),
        ] {
            let store = modeled_protected_classification_store();
            store
                .record_authorization_release_intent(&release("unknown", &unknown, "10"))
                .unwrap();
            assert!(matches!(
                store.retained_financial_input_exclusions("synthetic-account"),
                Err(StoreError::RecoveryRequired)
            ));
            assert_eq!(store.outstanding_debit("synthetic-account").unwrap(), "10");
        }
    }

    #[test]
    fn modeled_generation_flag_denies_even_when_local_rows_are_empty() {
        let store = modeled_generation_denial_store();
        assert!(
            store
                .account_exposures("synthetic-account")
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            store.retained_financial_input_exclusions("synthetic-account"),
            Err(StoreError::RecoveryRequired)
        ));
        assert!(matches!(
            store.retained_financial_input_exclusions("never-seen-account"),
            Err(StoreError::RecoveryRequired)
        ));
        assert!(matches!(
            store.require_ordinary_financial_lineage(
                "fresh-agreement",
                "fresh-obligation",
                "owner",
                None,
                &[]
            ),
            Err(StoreError::RecoveryRequired)
        ));
    }

    #[test]
    fn modeled_restore_marker_denies_empty_inputs_without_generation_flag() {
        let store = modeled_protected_classification_store();
        store.connection.lock().unwrap().execute(
            "UPDATE store_recovery SET recovery_required=1,restored_at_ms=1,source_snapshot_digest=?1 WHERE singleton=1", [&"a".repeat(64)],
        ).unwrap();
        assert!(matches!(
            store.retained_financial_input_exclusions("synthetic-account"),
            Err(StoreError::RecoveryRequired)
        ));
        assert!(matches!(
            store.require_ordinary_financial_lineage(
                "fresh-agreement",
                "fresh-obligation",
                "owner",
                None,
                &[]
            ),
            Err(StoreError::RecoveryRequired)
        ));
    }

    #[test]
    fn old_obligation_and_record_fences_survive_new_agreement_labels() {
        let store = modeled_generation_denial_store();
        add_fence(&store, "obligation", "old-obligation");
        add_fence(&store, "record", "agreement:old-agreement");
        let c = store.connection.lock().unwrap();
        assert!(matches!(
            require_lineage_fences(
                &store,
                &c,
                "new-label",
                "old-obligation",
                "owner",
                None,
                &[]
            ),
            Err(StoreError::RecoveryRequired)
        ));
        assert!(matches!(
            require_lineage_fences(
                &store,
                &c,
                "old-agreement",
                "new-obligation",
                "owner",
                None,
                &[]
            ),
            Err(StoreError::RecoveryRequired)
        ));
        // Predicate success is not admission: the full method still denies the
        // manually modeled flag, as the preceding predicate test checks.
        assert!(
            require_lineage_fences(
                &store,
                &c,
                "new-label",
                "new-obligation",
                "owner",
                None,
                &[]
            )
            .is_ok()
        );
    }

    #[test]
    fn old_idempotency_operation_and_effect_identities_reject_before_global_gate() {
        let store = modeled_generation_denial_store();
        let principal = "synthetic-owner";
        let key = "original-stable-key-0001";
        let identity = request_digest(&serde_json::json!([principal, key])).unwrap();
        add_fence(&store, "idempotency", &identity);
        add_fence(&store, "operation", "old-operation");
        add_fence(&store, "effect", "old-effect");
        let c = store.connection.lock().unwrap();
        assert!(matches!(
            require_lineage_fences(
                &store,
                &c,
                "new",
                "new-obligation",
                principal,
                Some(key),
                &[]
            ),
            Err(StoreError::RecoveryRequired)
        ));
        for operation in ["old-operation", "old-effect"] {
            assert!(matches!(
                require_lineage_fences(
                    &store,
                    &c,
                    "new",
                    "new-obligation",
                    principal,
                    None,
                    &[operation]
                ),
                Err(StoreError::RecoveryRequired)
            ));
        }
        assert!(
            require_lineage_fences(
                &store,
                &c,
                "new",
                "new-obligation",
                "different-owner",
                Some(key),
                &[]
            )
            .is_ok()
        );
        assert!(
            require_lineage_fences(
                &store,
                &c,
                "new",
                "new-obligation",
                principal,
                Some("new-stable-key-0002"),
                &["new-operation"]
            )
            .is_ok()
        );
    }

    #[test]
    fn ordinary_obligation_loss_fence_is_not_evaded_by_new_agreement_identity() {
        let store = modeled_protected_classification_store();
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO records VALUES('settlement_applied','synthetic-loss',0,?1,1,1)",
                [encode(&serde_json::json!("old-obligation")).unwrap()],
            )
            .unwrap();
        assert!(matches!(
            store.require_ordinary_financial_lineage(
                "new-agreement",
                "old-obligation",
                "owner",
                None,
                &[]
            ),
            Err(StoreError::RecoveryRequired)
        ));
        assert!(
            store
                .require_ordinary_financial_lineage(
                    "new-agreement",
                    "unrelated-obligation",
                    "owner",
                    None,
                    &[]
                )
                .is_ok()
        );
    }
    #[test]
    fn local_snapshot_unions_alias_exposure_without_releasing_recovery_guard() {
        let store = modeled_protected_classification_store();
        store
            .initialize_authority_account("synthetic-alias", 1)
            .unwrap();
        let canonical_input = "a".repeat(64);
        let alias_input = "b".repeat(64);
        store
            .record_authorization_release_intent(&release("canonical", &canonical_input, "10"))
            .unwrap();
        let mut alias = release("alias", &alias_input, "20");
        alias.account_id = "synthetic-alias".into();
        store.record_authorization_release_intent(&alias).unwrap();
        let c = store.connection.lock().unwrap();
        let snapshot = read_retained_input_exclusions(
            &c,
            "synthetic-account",
            &BTreeSet::from(["synthetic-account".into(), "synthetic-alias".into()]),
        )
        .unwrap();
        assert_eq!(snapshot.account_id(), "synthetic-account");
        assert!(snapshot.excludes("unrelated", &canonical_input));
        assert!(snapshot.excludes("unrelated", &alias_input));
        assert!(read_retained_input_exclusions(&c, "synthetic-account", &BTreeSet::new()).is_err());
        assert!(
            read_retained_input_exclusions(
                &c,
                "synthetic-account",
                &BTreeSet::from(["synthetic-alias".into()])
            )
            .is_err()
        );
        drop(c);
        let recovered = modeled_generation_denial_store();
        assert!(matches!(
            recovered.retained_financial_input_exclusions("synthetic-account"),
            Err(StoreError::RecoveryRequired)
        ));
    }
}
