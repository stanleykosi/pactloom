//! Consistent local historical snapshot, with no active-writer/session lease.
//! This never changes exclusion, acknowledgement, recovery flags or exposure.
use super::*;
use crate::authority_bridge::retired_history::RetiredLocalAudit;
use rusqlite::TransactionBehavior;
use wholepact_authority::account_use::AccountUseGenesis;

pub(crate) struct RetiredLocalSnapshot {
    binding: SignerJournalBinding,
    audit: RetiredLocalAudit,
}
impl RetiredLocalSnapshot {
    pub(crate) fn audit(&self) -> &RetiredLocalAudit {
        &self.audit
    }
    pub(crate) fn same_original(&self, other: &Self) -> bool {
        self.binding == other.binding && self.audit == other.audit
    }
}
impl SignerConsentJournal {
    /// Requires immutable local genesis, but deliberately does not obtain a
    /// SignerConsentSession or reject merely because a historical recovery flag
    /// is true. Unknown legacy is denied, not retrospectively upgraded.
    pub(crate) fn retired_history_snapshot(
        &self,
        expected: &AccountUseGenesis,
    ) -> Result<RetiredLocalSnapshot> {
        expected
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        let _fence = self
            .authority_fence
            .try_write()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
        storage::bounded(&tx, self.capacity_limits())?;
        offline_history::require_legacy_journal(&tx)?;
        let account = storage::read_account(&tx)?;
        let stored = account_use_storage::inspect(&tx, &account.account_id)?;
        let genesis = stored.genesis().ok_or(JournalError::RecoveryRequired)?;
        if genesis != expected || account.account_id != expected.identity.account_id {
            return Err(JournalError::InvalidBinding);
        }
        let audit = RetiredLocalAudit {
            genesis: genesis.clone(),
            local_exclusion: stored.exclusion().cloned(),
            local_witness_ack: stored.witness_ack().cloned(),
            recovery_required: account.recovery_required,
            historical_writer_epoch: account.writer_epoch,
        };
        // This deferred transaction provides one SQLite read snapshot, including
        // other Store/connection activity. It reserves nothing and is released
        // before native consideration or any remote operation.
        tx.commit()?;
        Ok(RetiredLocalSnapshot {
            binding: self.binding(),
            audit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_fresh_legacy_journal_cannot_supply_born_history_and_is_unchanged() {
        use wholepact_authority::account_use::AccountUseIdentity;
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = wholepact_storage_security::DatabaseKey::from_bytes([71; 32]);
        let account = "a".repeat(64);
        let private_directory = crate::files::PrivateDirectory::open(dir.path()).unwrap();
        let journal = SignerConsentJournal::create_encrypted(
            &dir.path().join("signer"),
            &key,
            &account,
            1,
            false,
            &private_directory
                .signer_journal_source_owner_for_test(&dir.path().join("signer"))
                .unwrap(),
        )
        .unwrap();
        let expected = AccountUseGenesis {
            version: 1,
            identity: AccountUseIdentity {
                account_id: account,
                full_viewing_key_digest: "b".repeat(64),
                network_profile_id: "ironwood-testnet-nu7-candidate".into(),
                derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
            },
            witness_id: "witness-a".into(),
            witness_origin_digest: "c".repeat(64),
            owner_certificate_digest: "d".repeat(64),
            native_birth_digest: "e".repeat(64),
        };
        let before = journal.account_state().unwrap();
        assert!(matches!(
            journal.retired_history_snapshot(&expected),
            Err(JournalError::RecoveryRequired)
        ));
        assert!(before == journal.account_state().unwrap());
        assert!(
            account_use_storage::inspect(&journal.connection.lock().unwrap(), &before.account_id)
                .unwrap()
                .genesis()
                .is_none()
        );
        // No recovered-generation/native/witness success is modeled by this test.
    }
}
