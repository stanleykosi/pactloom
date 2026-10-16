//! Source-qualified settlement application and conservative invalidation.
use crate::{Result, Store, StoreError, StoredRecord, encode, now_ms};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

impl Store {
    pub fn settlement_obligation_requires_recovery(&self, obligation: &str) -> Result<bool> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        if self.generation_fenced(&c, "obligation", obligation)? {
            return Ok(true);
        }
        Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM records WHERE aggregate_type='settlement_applied' AND payload=?1)",[encode(&serde_json::json!(obligation))?],|r|r.get(0))?)
    }

    pub fn settlement_affected_accounts(&self, obligation: &str) -> Result<Vec<String>> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let mut q=c.prepare("SELECT DISTINCT account_id FROM authority_exposures WHERE obligation_id=?1 ORDER BY account_id")?;
        let rows = q
            .query_map([obligation], |r| r.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Durable destination identity, generated inside this store. Reopened stores
    /// retain their destination; runtime leases must still bind the actual handle.
    pub fn settlement_destination(&self) -> Result<String> {
        let c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        if self.recovered_generation {
            let id = self.current_recovered_settlement_identity(&c)?;
            return Ok(format!("store-{id}"));
        }
        c.execute("INSERT OR IGNORE INTO records(aggregate_type,id,revision,payload,created_at_ms,updated_at_ms) VALUES('settlement_identity','local',0,json_quote(lower(hex(randomblob(32)))),?1,?1)", [now_ms()])?;
        let encoded: String = c.query_row(
            "SELECT payload FROM records WHERE aggregate_type='settlement_identity' AND id='local'",
            [],
            |r| r.get(0),
        )?;
        let id: String = serde_json::from_str(&encoded)?;
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(format!("store-{id}"))
    }

    /// All agreement revisions must still match the complete snapshot. Updating
    /// participant archives, reopening every alternative and fencing accounts is
    /// one transaction. Evidence checkpoints are included in ordinary backups.
    pub fn reopen_settlement_obligation(
        &self,
        evidence_id: &str,
        obligation: &str,
        snapshot: &[StoredRecord],
        affected_accounts: &[String],
        updates: &[(String, serde_json::Value)],
    ) -> Result<()> {
        crate::validate_id(evidence_id)?;
        crate::validate_id(obligation)?;
        let mut c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if self.generation_fenced(&tx, "obligation", obligation)? {
            return Err(StoreError::RecoveryRequired);
        }
        let checkpoint: Option<String> = tx
            .query_row(
                "SELECT payload FROM records WHERE aggregate_type='settlement_applied' AND id=?1",
                [evidence_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = checkpoint {
            if old != encode(&serde_json::json!(obligation))? {
                return Err(StoreError::IdempotencyConflict);
            }
            return Ok(());
        }
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM records WHERE aggregate_type='settlement_applied'",
            [],
            |r| r.get(0),
        )?;
        if count >= 8192 {
            return Err(StoreError::ResourceExhausted);
        }
        let accounts: Vec<String> = {
            let mut q=tx.prepare("SELECT DISTINCT account_id FROM authority_exposures WHERE obligation_id=?1 ORDER BY account_id")?;
            let rows = q
                .query_map([obligation], |r| r.get(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        if accounts.iter().any(|a| !affected_accounts.contains(a)) {
            return Err(StoreError::RevisionConflict);
        }
        let revisions: Vec<(String, u64)> = {
            let mut q = tx.prepare(
                "SELECT id,revision FROM records WHERE aggregate_type='agreement' ORDER BY id",
            )?;
            let rows = q
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        let mut expected: Vec<_> = snapshot
            .iter()
            .map(|r| (r.id.clone(), r.revision))
            .collect();
        expected.sort();
        if revisions != expected {
            return Err(StoreError::RevisionConflict);
        }
        for (id, payload) in updates {
            let original = snapshot
                .iter()
                .find(|r| &r.id == id)
                .ok_or(StoreError::RevisionConflict)?;
            let next = original
                .revision
                .checked_add(1)
                .ok_or(StoreError::RevisionConflict)?;
            tx.execute("UPDATE records SET revision=?2,payload=?3,updated_at_ms=?4 WHERE aggregate_type='agreement' AND id=?1",params![id,next,encode(payload)?,now_ms()])?;
            tx.execute("INSERT INTO events(aggregate_type,aggregate_id,aggregate_revision,kind,payload,operation_id,occurred_at_ms) VALUES('agreement',?1,?2,'settlement_confidence_invalidated','{}',?3,?4)",params![id,next,evidence_id,now_ms()])?;
        }
        for account in affected_accounts {
            tx.execute(
                "UPDATE authority_accounts SET recovery_required=1 WHERE account_id=?1",
                [account],
            )?;
        }
        let exposures: Vec<(String, String, String)> = {
            let mut q=tx.prepare("SELECT authorization_id,account_id,payload FROM authority_exposures WHERE obligation_id=?1")?;
            let rows = q
                .query_map([obligation], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        for (authorization, account, payload) in exposures {
            let intent: crate::authority::ReleaseIntent = serde_json::from_str(&payload)?;
            tx.execute("UPDATE authority_exposures SET state='outstanding_uncertain',updated_at_ms=?2 WHERE authorization_id=?1",params![authorization,now_ms()])?;
            tx.execute(
                "UPDATE authority_accounts SET recovery_required=1 WHERE account_id=?1",
                [&account],
            )?;
            for input in intent.input_ids {
                tx.execute("INSERT OR IGNORE INTO authority_reservations(account_id,input_id,authorization_id) VALUES(?1,?2,?3)",params![account,input,authorization])?;
            }
            tx.execute("INSERT INTO authority_events(authorization_id,kind,evidence_ref,occurred_at_ms) VALUES(?1,'settlement_confidence_invalidated',?2,?3)",params![authorization,evidence_id,now_ms()])?;
        }
        tx.execute("INSERT INTO records(aggregate_type,id,revision,payload,created_at_ms,updated_at_ms) VALUES('settlement_applied',?1,0,?2,?3,?3)",params![evidence_id,encode(&serde_json::json!(obligation))?,now_ms()])?;
        tx.commit()?;
        Ok(())
    }
}

impl Store {
    /// Native integration supplies an authenticated exact original release and a
    /// live check held across this transaction. This low-level storage operation
    /// is not a public API DTO or a source of chain authority.
    /// Missing mirrors are retained in a quarantined account: one original never
    /// establishes that the coordinator has the signer's complete budget history.
    pub fn consume_exact_settlement_release(
        &self,
        intent: &crate::authority::ReleaseIntent,
        evidence_id: &str,
        provenance: &serde_json::Value,
        snapshot: &[StoredRecord],
        updates: &[(String, serde_json::Value)],
        check_live: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        self.commit_exact_settlement_release(
            intent,
            evidence_id,
            provenance,
            snapshot,
            updates,
            check_live,
            false,
        )
    }
    /// Retains a source-qualified alternative link without freeing a single
    /// original debit or reservation. A later all-alternative reconciliation
    /// protocol, separately approved, is required before replacement is possible.
    pub fn retain_exact_conflict_release(
        &self,
        intent: &crate::authority::ReleaseIntent,
        evidence_id: &str,
        provenance: &serde_json::Value,
        snapshot: &[StoredRecord],
        updates: &[(String, serde_json::Value)],
        check_live: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        self.commit_exact_settlement_release(
            intent,
            evidence_id,
            provenance,
            snapshot,
            updates,
            check_live,
            true,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn commit_exact_settlement_release(
        &self,
        intent: &crate::authority::ReleaseIntent,
        evidence_id: &str,
        provenance: &serde_json::Value,
        snapshot: &[StoredRecord],
        updates: &[(String, serde_json::Value)],
        check_live: &dyn Fn() -> Result<()>,
        conflict: bool,
    ) -> Result<()> {
        let state = if conflict {
            "outstanding_uncertain"
        } else {
            "consumed"
        };
        let checkpoint_kind = if conflict {
            "settlement_conflict"
        } else {
            "settlement_consumed"
        };
        let event_kind = if conflict {
            "canonical_conflict"
        } else {
            "consumed"
        };
        let record_event = if conflict {
            "settlement_conflict_observed"
        } else {
            "settlement_consumption_observed"
        };
        crate::validate_id(evidence_id)?;
        crate::authority::validate_intent(intent)?;
        if self.protection() != crate::StorageProtection::Encrypted {
            return Err(StoreError::RecoveryRequired);
        }
        let checkpoint_id =
            crate::request_digest(&serde_json::json!([evidence_id, intent.authorization_id]))?;
        let checkpoint = encode(&serde_json::json!({
            "release": intent, "evidence_id": evidence_id, "provenance": provenance
        }))?;
        let mut c = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if crate::backup::read_recovery_state(&tx)?.recovery_required && !self.recovered_generation
        {
            return Err(StoreError::RecoveryRequired);
        }
        if self.generation_fenced(&tx, "obligation", &intent.obligation_id)? {
            return Err(StoreError::RecoveryRequired);
        }
        for (id, payload) in updates {
            self.require_current_record_write(&tx, "agreement", id, payload)?;
        }
        let fenced: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM records WHERE aggregate_type='settlement_applied' AND payload=?1)", [encode(&serde_json::json!(intent.obligation_id))?], |r| r.get(0))?;
        if fenced {
            return Err(StoreError::RecoveryRequired);
        }
        let revisions: Vec<(String, u64)> = {
            let mut q = tx.prepare(
                "SELECT id,revision FROM records WHERE aggregate_type='agreement' ORDER BY id",
            )?;
            let rows = q
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        let mut expected: Vec<_> = snapshot
            .iter()
            .map(|r| (r.id.clone(), r.revision))
            .collect();
        expected.sort();
        if revisions != expected {
            return Err(StoreError::RevisionConflict);
        }
        let old_checkpoint: Option<String> = tx
            .query_row(
                &format!(
                    "SELECT payload FROM records WHERE aggregate_type='{checkpoint_kind}' AND id=?1"
                ),
                [&checkpoint_id],
                |r| r.get(0),
            )
            .optional()?;
        let replayed = if let Some(old) = old_checkpoint {
            if old != checkpoint {
                return Err(StoreError::IdempotencyConflict);
            }
            let current: Option<(String, String)> = tx
                .query_row(
                    "SELECT payload,state FROM authority_exposures WHERE authorization_id=?1",
                    [&intent.authorization_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (payload, current_state) = current.ok_or(StoreError::RecoveryRequired)?;
            if current_state != state
                || serde_json::from_str::<crate::authority::ReleaseIntent>(&payload)? != *intent
            {
                return Err(StoreError::RecoveryRequired);
            }
            true
        } else {
            false
        };
        if !replayed {
            let count: i64 = tx.query_row(
                &format!("SELECT count(*) FROM records WHERE aggregate_type='{checkpoint_kind}'"),
                [],
                |r| r.get(0),
            )?;
            if count >= 8192 {
                return Err(StoreError::ResourceExhausted);
            }
            let old: Option<(String, String, bool)> = tx.query_row("SELECT payload,state,release_intent FROM authority_exposures WHERE authorization_id=?1", [&intent.authorization_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            if let Some((payload, old_state, released)) = old {
                let original: crate::authority::ReleaseIntent = serde_json::from_str(&payload)?;
                if original != *intent || !released {
                    return Err(StoreError::IdempotencyConflict);
                }
                if !matches!(
                    old_state.as_str(),
                    "authorized_locally" | "released" | "outstanding_uncertain" | "consumed"
                ) || (conflict && old_state == "consumed")
                {
                    return Err(StoreError::InvalidTransition);
                }
            } else {
                // Do not silently enroll a ready account or invent missing originals.
                let epoch = i64::try_from(intent.writer_epoch)
                    .map_err(|_| StoreError::InvalidInput("writer epoch overflow"))?;
                tx.execute("INSERT OR IGNORE INTO authority_accounts(account_id,writer_epoch,recovery_required) VALUES(?1,?2,1)", params![intent.account_id,epoch])?;
                tx.execute(
                    "UPDATE authority_accounts SET recovery_required=1 WHERE account_id=?1",
                    [&intent.account_id],
                )?;
                let value = serde_json::to_value(intent)?;
                tx.execute(&format!("INSERT INTO authority_exposures(authorization_id,account_id,obligation_id,proposal_id,request_digest,maximum_debit,state,release_intent,payload,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,?6,'{state}',1,?7,?8,?8)"),params![intent.authorization_id,intent.account_id,intent.obligation_id,intent.proposal_id,crate::request_digest(&value)?,intent.maximum_debit,encode(&value)?,now_ms()])?;
            }
            tx.execute(&format!("UPDATE authority_exposures SET state='{state}',updated_at_ms=?2 WHERE authorization_id=?1"), params![intent.authorization_id,now_ms()])?;
            if conflict {
                for input in &intent.input_ids {
                    tx.execute("INSERT OR IGNORE INTO authority_reservations(account_id,input_id,authorization_id) VALUES(?1,?2,?3)", params![intent.account_id,input,intent.authorization_id])?;
                }
            } else {
                tx.execute(
                    "DELETE FROM authority_reservations WHERE authorization_id=?1",
                    [&intent.authorization_id],
                )?;
            }
            tx.execute(&format!("INSERT INTO authority_events(authorization_id,kind,evidence_ref,occurred_at_ms) VALUES(?1,'{event_kind}',?2,?3)"), params![intent.authorization_id,evidence_id,now_ms()])?;
            tx.execute(&format!("INSERT INTO records(aggregate_type,id,revision,payload,created_at_ms,updated_at_ms) VALUES('{checkpoint_kind}',?1,0,?2,?3,?3)"),params![checkpoint_id,checkpoint,now_ms()])?;
        }
        for (id, payload) in updates {
            let original = snapshot
                .iter()
                .find(|r| &r.id == id)
                .ok_or(StoreError::RevisionConflict)?;
            let next = original
                .revision
                .checked_add(1)
                .ok_or(StoreError::RevisionConflict)?;
            tx.execute("UPDATE records SET revision=?2,payload=?3,updated_at_ms=?4 WHERE aggregate_type='agreement' AND id=?1",params![id,next,encode(payload)?,now_ms()])?;
            tx.execute(&format!("INSERT INTO events(aggregate_type,aggregate_id,aggregate_revision,kind,payload,operation_id,occurred_at_ms) VALUES('agreement',?1,?2,'{record_event}','{{}}',?3,?4)"),params![id,next,evidence_id,now_ms()])?;
        }
        check_live()?;
        tx.commit()?;
        Ok(())
    }
}
