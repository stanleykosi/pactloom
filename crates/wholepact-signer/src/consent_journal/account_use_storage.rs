//! Unlinked signer-owned immutable storage kernel. No production mutation entry
//! point or native issuer exists yet. The private append helpers are exercised
//! only by synthetic tests until actual native/witness owners are integrated.
use super::*;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use wholepact_authority::account_use::{AccountUseGenesis, PermanentAccountExclusion};

pub(super) struct StoredAccountUse {
    genesis: Option<AccountUseGenesis>,
    exclusion: Option<PermanentAccountExclusion>,
    witness_ack: Option<wholepact_authority::account_use_link::AccountExclusionReceipt>,
}
impl StoredAccountUse {
    pub(super) fn genesis(&self) -> Option<&AccountUseGenesis> {
        self.genesis.as_ref()
    }
    pub(super) fn exclusion(&self) -> Option<&PermanentAccountExclusion> {
        self.exclusion.as_ref()
    }
    pub(super) fn witness_ack(
        &self,
    ) -> Option<&wholepact_authority::account_use_link::AccountExclusionReceipt> {
        self.witness_ack.as_ref()
    }
    // Historical projection only. Fresh session/witness/native authority is not
    // available from these rows, even when genesis is present and no exclusion.
}
pub(super) fn inspect(c: &Connection, actual_account_id: &str) -> Result<StoredAccountUse> {
    if c.is_autocommit() {
        let tx = Transaction::new_unchecked(c, TransactionBehavior::Deferred)?;
        inspect_rows(&tx, actual_account_id)
    } else {
        inspect_rows(c, actual_account_id)
    }
}
fn inspect_tx(c: &Transaction<'_>, actual_account_id: &str) -> Result<StoredAccountUse> {
    inspect_rows(c, actual_account_id)
}
fn inspect_rows(c: &Connection, actual_account_id: &str) -> Result<StoredAccountUse> {
    let rows = c.query_row("SELECT account_id,full_viewing_key_digest,genesis_digest,payload FROM signer_account_use_genesis WHERE singleton=1", [], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?))).optional()?;
    let exclusion = c.query_row("SELECT genesis_digest,exclusion_digest,payload FROM signer_account_use_exclusion WHERE singleton=1", [], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))).optional()?;
    let ack_count: u64 = c.query_row(
        "SELECT count(*) FROM signer_account_use_witness_ack",
        [],
        |r| r.get(0),
    )?;
    if ack_count > 1 {
        return Err(JournalError::InvalidBinding);
    }
    let ack = c.query_row("SELECT exclusion_digest,witness_origin_digest,committed_head_digest,receipt_digest,payload FROM signer_account_use_witness_ack", [], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?))).optional()?;
    let Some((account, fvk, commitment, payload)) = rows else {
        if exclusion.is_some() || ack.is_some() {
            return Err(JournalError::InvalidBinding);
        }
        return Ok(StoredAccountUse {
            genesis: None,
            exclusion: None,
            witness_ack: None,
        });
    };
    let genesis: AccountUseGenesis = decode(payload)?;
    if account != actual_account_id
        || genesis.identity.account_id != account
        || genesis.identity.full_viewing_key_digest != fvk
        || genesis.digest().map_err(|_| JournalError::InvalidBinding)? != commitment
    {
        return Err(JournalError::InvalidBinding);
    }
    let exclusion = exclusion
        .map(|(parent, digest, payload)| {
            let event: PermanentAccountExclusion = decode(payload)?;
            if parent != commitment
                || event.genesis_digest != parent
                || event.identity != genesis.identity
                || event.digest().map_err(|_| JournalError::InvalidBinding)? != digest
            {
                return Err(JournalError::InvalidBinding);
            }
            Ok(event)
        })
        .transpose()?;
    let witness_ack = ack
        .map(|(parent, origin, head, digest, payload)| {
            let evidence: wholepact_authority::account_use_link::AccountExclusionReceipt =
                decode(payload)?;
            let exclusion = exclusion.as_ref().ok_or(JournalError::InvalidBinding)?;
            if parent
                != exclusion
                    .digest()
                    .map_err(|_| JournalError::InvalidBinding)?
                || evidence.exclusion_digest != parent
                || evidence.genesis_digest != commitment
                || evidence.operation_id != exclusion.operation_id
                || evidence.witness_origin_digest != genesis.witness_origin_digest
                || evidence.witness_origin_digest != origin
                || evidence.committed_head.digest != head
                || evidence
                    .digest()
                    .map_err(|_| JournalError::InvalidBinding)?
                    != digest
            {
                return Err(JournalError::InvalidBinding);
            }
            Ok(evidence)
        })
        .transpose()?;
    Ok(StoredAccountUse {
        genesis: Some(genesis),
        exclusion,
        witness_ack,
    })
}
// These private helpers are not native approval conversions. No production
// caller is supplied. Future public(super) journal methods must accept the real
// opaque native birth/exclusion decisions and authenticated witness receipt.
// Model-only insertion until the genuine pending birth issuer is connected.
#[cfg(test)]
fn append_genesis(
    tx: &Transaction<'_>,
    actual_account_id: &str,
    genesis: &AccountUseGenesis,
) -> Result<()> {
    let current = inspect_tx(tx, actual_account_id)?;
    let commitment = genesis.digest().map_err(|_| JournalError::InvalidBinding)?;
    if genesis.identity.account_id != actual_account_id {
        return Err(JournalError::InvalidBinding);
    }
    if let Some(old) = current.genesis {
        return if old == *genesis {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        };
    }
    tx.execute(
        "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
        params![
            actual_account_id,
            genesis.identity.full_viewing_key_digest,
            commitment,
            encode(genesis)?.as_str()
        ],
    )?;
    Ok(())
}
pub(super) fn append_exclusion(
    tx: &Transaction<'_>,
    actual_account_id: &str,
    event: &PermanentAccountExclusion,
) -> Result<()> {
    let current = inspect_tx(tx, actual_account_id)?;
    let genesis = current.genesis.ok_or(JournalError::RecoveryRequired)?;
    let commitment = event.digest().map_err(|_| JournalError::InvalidBinding)?;
    if event.identity != genesis.identity
        || event.genesis_digest != genesis.digest().map_err(|_| JournalError::InvalidBinding)?
    {
        return Err(JournalError::InvalidBinding);
    }
    if let Some(old) = current.exclusion {
        return if old == *event {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        };
    }
    tx.execute(
        "INSERT INTO signer_account_use_exclusion VALUES(1,?1,?2,?3)",
        params![event.genesis_digest, commitment, encode(event)?.as_str()],
    )?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use wholepact_authority::account_use::{AccountUseIdentity, ExclusionReason};
    fn genesis() -> AccountUseGenesis {
        AccountUseGenesis {
            version: 1,
            identity: AccountUseIdentity {
                account_id: "11".repeat(32),
                full_viewing_key_digest: "22".repeat(32),
                network_profile_id: "synthetic".into(),
                derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
            },
            witness_id: "witness".into(),
            witness_origin_digest: "88".repeat(32),
            owner_certificate_digest: "33".repeat(32),
            native_birth_digest: "44".repeat(32),
        }
    }
    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        c.execute_batch(include_str!("account_use_schema.sql"))
            .unwrap();
        c
    }
    #[test]
    fn empty_migration_is_unknown_and_cannot_retire_without_genesis() {
        let mut c = db();
        let g = genesis();
        assert!(
            inspect(&c, &g.identity.account_id)
                .unwrap()
                .genesis()
                .is_none()
        );
        let e = PermanentAccountExclusion {
            version: 1,
            identity: g.identity.clone(),
            genesis_digest: g.digest().unwrap(),
            operation_id: "retire".into(),
            native_review_digest: "55".repeat(32),
            reason: ExclusionReason::RetirementRequested,
        };
        let tx = c.transaction().unwrap();
        assert!(matches!(
            append_exclusion(&tx, &g.identity.account_id, &e),
            Err(JournalError::RecoveryRequired)
        ));
    }
    #[test]
    fn archived_ack_claim_cannot_override_local_identity() {
        let mut c = db();
        let g = genesis();
        let e = PermanentAccountExclusion {
            version: 1,
            identity: g.identity.clone(),
            genesis_digest: g.digest().unwrap(),
            operation_id: "retire".into(),
            native_review_digest: "55".repeat(32),
            reason: ExclusionReason::RetirementRequested,
        };
        let tx = c.transaction().unwrap();
        append_genesis(&tx, &g.identity.account_id, &g).unwrap();
        append_exclusion(&tx, &g.identity.account_id, &e).unwrap();
        // Deliberately untrusted archive row, NOT an authenticated receipt wrapper.
        let claim = wholepact_authority::account_use_link::AccountExclusionReceipt {
            genesis_digest: "99".repeat(32),
            exclusion_digest: e.digest().unwrap(),
            witness_origin_digest: "88".repeat(32),
            committed_head: wholepact_authority::AuthorityHead {
                sequence: 1,
                digest: "77".repeat(32),
            },
            operation_id: e.operation_id.clone(),
        };
        tx.execute(
            "INSERT INTO signer_account_use_witness_ack VALUES(?1,?2,?3,?4,?5)",
            params![
                claim.exclusion_digest,
                claim.witness_origin_digest,
                claim.committed_head.digest,
                claim.digest().unwrap(),
                serde_json::to_string(&claim).unwrap()
            ],
        )
        .unwrap();
        tx.commit().unwrap();
        assert!(matches!(
            inspect(&c, &g.identity.account_id),
            Err(JournalError::InvalidBinding)
        ));
        assert!(
            c.execute("DELETE FROM signer_account_use_witness_ack", [])
                .is_err()
        );
        assert!(
            c.execute(
                "UPDATE signer_account_use_witness_ack SET receipt_digest='bad'",
                []
            )
            .is_err()
        );
    }
    #[test]
    fn immutable_rows_exact_retry_and_conflict() {
        let mut c = db();
        let g = genesis();
        let tx = c.transaction().unwrap();
        append_genesis(&tx, &g.identity.account_id, &g).unwrap();
        append_genesis(&tx, &g.identity.account_id, &g).unwrap();
        let mut other = g.clone();
        other.native_birth_digest = "66".repeat(32);
        assert!(matches!(
            append_genesis(&tx, &g.identity.account_id, &other),
            Err(JournalError::Conflict)
        ));
        let e = PermanentAccountExclusion {
            version: 1,
            identity: g.identity.clone(),
            genesis_digest: g.digest().unwrap(),
            operation_id: "retire".into(),
            native_review_digest: "55".repeat(32),
            reason: ExclusionReason::RetirementRequested,
        };
        append_exclusion(&tx, &g.identity.account_id, &e).unwrap();
        append_exclusion(&tx, &g.identity.account_id, &e).unwrap();
        tx.commit().unwrap();
        assert!(
            inspect(&c, &g.identity.account_id)
                .unwrap()
                .exclusion()
                .is_some()
        );
        assert!(
            c.execute("DELETE FROM signer_account_use_exclusion", [])
                .is_err()
        );
        assert!(
            c.execute("UPDATE signer_account_use_genesis SET payload='{}'", [])
                .is_err()
        );
        assert!(c.execute("INSERT OR REPLACE INTO signer_account_use_genesis SELECT * FROM signer_account_use_genesis", []).is_err());
        assert!(c.execute("INSERT OR REPLACE INTO signer_account_use_exclusion SELECT * FROM signer_account_use_exclusion", []).is_err());
    }
}

/// Historical witness acknowledgement only; cannot activate an account. The
/// opaque input is constructed exclusively by full authority-history replay.
/// Actual caller must also bind its ORIGINAL vault witness disclosure before
/// obtaining it; there is deliberately no public caller in this stage.
pub(super) fn append_witness_ack(
    tx: &Transaction<'_>,
    actual_account_id: &str,
    reconciled: &wholepact_authority::account_use_link::ReconciledAccountExclusion,
) -> Result<()> {
    let retained = inspect_tx(tx, actual_account_id)?;
    let g = retained.genesis().ok_or(JournalError::RecoveryRequired)?;
    let e = retained.exclusion().ok_or(JournalError::RecoveryRequired)?;
    let evidence = reconciled.evidence();
    if evidence.genesis_digest != g.digest().map_err(|_| JournalError::InvalidBinding)?
        || evidence.exclusion_digest != e.digest().map_err(|_| JournalError::InvalidBinding)?
        || evidence.witness_origin_digest != g.witness_origin_digest
        || evidence.operation_id != e.operation_id
    {
        return Err(JournalError::InvalidBinding);
    }
    let receipt_digest = reconciled
        .receipt_digest()
        .map_err(|_| JournalError::InvalidBinding)?;
    let payload = serde_json::to_string(evidence).map_err(|_| JournalError::InvalidBinding)?;
    let old = tx.query_row(
        "SELECT witness_origin_digest,committed_head_digest,receipt_digest,payload FROM signer_account_use_witness_ack WHERE exclusion_digest=?1",
        [&evidence.exclusion_digest], |r| Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,String>(2)?, r.get::<_,String>(3)?)),
    ).optional()?;
    if let Some(old) = old {
        return if old
            == (
                evidence.witness_origin_digest.clone(),
                evidence.committed_head.digest.clone(),
                receipt_digest,
                payload,
            ) {
            Ok(())
        } else {
            Err(JournalError::Conflict)
        };
    }
    tx.execute("INSERT INTO signer_account_use_witness_ack(exclusion_digest,witness_origin_digest,committed_head_digest,receipt_digest,payload) VALUES(?1,?2,?3,?4,?5)",
        params![evidence.exclusion_digest, evidence.witness_origin_digest, evidence.committed_head.digest, receipt_digest, payload])?;
    Ok(())
}

/// Ordinary legacy behavior is not upgraded into complete successor provenance.
/// Positive local exclusion still blocks new key use/consent; history stays readable.
pub(super) fn require_not_excluded(c: &Connection, actual_account_id: &str) -> Result<()> {
    if inspect(c, actual_account_id)?.exclusion().is_some() {
        return Err(JournalError::Permission);
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod backup_tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use wholepact_authority::account_use::{AccountUseIdentity, ExclusionReason};
    use wholepact_storage_security::{DatabaseKey, StorageSecurityError, bundle::*};
    #[test]
    fn encrypted_backup_restores_all_provenance_rows_and_remains_quarantined() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let account = "11".repeat(32);
        let key = DatabaseKey::from_bytes([41; 32]);
        let journal = SignerConsentJournal::create_encrypted(
            &dir.path().join("source.sqlite"),
            &key,
            &account,
            1,
            true,
        )
        .unwrap();
        // Modeled immutable historical rows. No native birth or witness approval
        // capability is fabricated; these cannot make the quarantined account usable.
        let genesis = AccountUseGenesis {
            version: 1,
            identity: AccountUseIdentity {
                account_id: account.clone(),
                full_viewing_key_digest: "22".repeat(32),
                network_profile_id: "synthetic-testnet".into(),
                derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
            },
            witness_id: "synthetic-witness".into(),
            witness_origin_digest: "33".repeat(32),
            owner_certificate_digest: "44".repeat(32),
            native_birth_digest: "55".repeat(32),
        };
        let exclusion = PermanentAccountExclusion {
            version: 1,
            identity: genesis.identity.clone(),
            genesis_digest: genesis.digest().unwrap(),
            operation_id: "retire".into(),
            native_review_digest: "66".repeat(32),
            reason: ExclusionReason::RetirementRequested,
        };
        let claim = wholepact_authority::account_use_link::AccountExclusionReceipt {
            genesis_digest: genesis.digest().unwrap(),
            exclusion_digest: exclusion.digest().unwrap(),
            witness_origin_digest: genesis.witness_origin_digest.clone(),
            operation_id: exclusion.operation_id.clone(),
            committed_head: wholepact_authority::AuthorityHead {
                sequence: 1,
                digest: "77".repeat(32),
            },
        };
        {
            let mut c = journal.connection.lock().unwrap();
            let tx = c.transaction().unwrap();
            append_genesis(&tx, &account, &genesis).unwrap();
            append_exclusion(&tx, &account, &exclusion).unwrap();
            // Raw test-only data insertion, deliberately not append_witness_ack.
            tx.execute(
                "INSERT INTO signer_account_use_witness_ack VALUES(?1,?2,?3,?4,?5)",
                params![
                    claim.exclusion_digest,
                    claim.witness_origin_digest,
                    claim.committed_head.digest,
                    claim.digest().unwrap(),
                    serde_json::to_string(&claim).unwrap()
                ],
            )
            .unwrap();
            tx.commit().unwrap();
            assert!(require_not_excluded(&c, &account).is_err());
        }
        let adapter = journal.backup_adapter();
        let sources = [RegisteredJournal::new("signer-authority", &adapter).unwrap()];
        let coverage = Coverage {
            present: BTreeMap::from([(
                JournalKind::SignerConsentAuthority,
                vec!["signer-authority".into()],
            )]),
            absent: BTreeSet::from([
                JournalKind::CoordinationAuthority,
                JournalKind::WalletScan,
                JournalKind::ProofWitness,
                JournalKind::SignedResults,
                JournalKind::ExactTransactions,
                JournalKind::Submission,
                JournalKind::TransportInbox,
                JournalKind::TransportOutbox,
            ]),
        };
        let archive = dir.path().join("archive.sqlite");
        let restored = dir.path().join("restored.sqlite");
        let archive_key = DatabaseKey::from_bytes([42; 32]);
        let restored_key = DatabaseKey::from_bytes([43; 32]);
        let gate = crate::consent_journal::tests::BackupGate;
        let manifest = snapshot(SnapshotRequest {
            principal_id: "synthetic-owner",
            profile_id: "synthetic-signer-profile",
            coverage,
            sources: &sources,
            destination: &archive,
            key: &archive_key,
            authority: &gate,
        })
        .unwrap();
        assert_eq!(manifest.components[0].schema_version, SCHEMA_VERSION);
        let report = test_restore(RestoreRequest {
            principal_id: "synthetic-owner",
            profile_id: "synthetic-signer-profile",
            archive: &archive,
            key: &archive_key,
            targets: &[RestoreTarget {
                component_id: "signer-authority",
                template: SignerConsentBundleAdapter::template(),
                destination: &restored,
                key: &restored_key,
            }],
            authority: &gate,
        })
        .unwrap();
        assert!(!report.authorization_allowed);
        assert!(matches!(
            SignerConsentJournal::open_encrypted(&restored, &restored_key, &account),
            Err(JournalError::Storage(
                StorageSecurityError::QuarantinedDatabase
            ))
        ));
        let source = recovery::VerifiedSignerRecoverySource::open(
            history::HistoryOpenRequest {
                archive: &archive,
                archive_key: &archive_key,
                component_id: "signer-authority",
                restored_component: &restored,
                restored_key: &restored_key,
            },
            SignerConsentBundleAdapter::template(),
        )
        .unwrap();
        for name in [
            "signer_account_use_genesis",
            "signer_account_use_exclusion",
            "signer_account_use_witness_ack",
        ] {
            assert_eq!(
                source
                    .tables()
                    .iter()
                    .find(|t| t.name() == name)
                    .unwrap()
                    .rows()
                    .len(),
                1
            );
        }
        assert!(source.tables().iter().find(|t|t.name()=="signer_account_use_exclusion").unwrap().rows()[0].cells().iter().any(|v|matches!(v,recovery::RecoveryCell::Text(t) if t==&serde_json::to_string(&exclusion).unwrap())));
    }
}
