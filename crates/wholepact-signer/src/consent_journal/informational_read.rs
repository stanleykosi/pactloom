//! Immutable original restored-source ownership; never a SignerConsentJournal.
use super::*;

pub(crate) struct QuarantinedJournalRead {
    source: VerifiedSignerRecoverySource,
    account_id: String,
    writer_epoch: u64,
}
impl QuarantinedJournalRead {
    pub(crate) fn from_verified(
        source: VerifiedSignerRecoverySource,
        expected: &str,
    ) -> Result<Self> {
        // A wallet component can contain viewing material. Until a verified
        // consuming authority-only projection exists, refuse rather than keep
        // those rows inside an allegedly key-free informational owner.
        if source.wallet().is_some() {
            return Err(JournalError::RecoveryRequired);
        }
        // Exact current layout only. No implicit migration or legacy genesis.
        if source.provenance().schema_version != SCHEMA_VERSION {
            return Err(JournalError::UnsupportedSchema);
        }
        let account = recovery_inventory::with_complete_source(&source, |tx| {
            let account = storage::read_account(tx)?;
            if account.account_id != expected {
                return Err(JournalError::InvalidBinding);
            }
            // The verified source proves the quarantined restored component is
            // exactly its original archive. The original account row may be
            // active: it is historical data and must not be rewritten here.
            Ok(account)
        })?;
        Ok(Self {
            source,
            account_id: account.account_id,
            writer_epoch: account.writer_epoch,
        })
    }
    pub(crate) fn account_id(&self) -> &str {
        &self.account_id
    }
    pub(crate) fn writer_epoch(&self) -> u64 {
        self.writer_epoch
    }
    pub(crate) fn checkpoint_id(&self) -> &str {
        &self.source.manifest().checkpoint_id
    }

    /// Complete historical projection of the sealed original signer source.
    /// This is not an admission: the caller must hold its independently issued
    /// native informational owner and recheck that owner's immutable source.
    /// No source account flag, epoch, receipt or historical audit row is changed.
    pub(crate) fn complete_history_v5(
        &self,
        history: &wholepact_authority::ReconciledAuthorityHistory,
    ) -> Result<crate::authority_bridge::host_recovery_ipc::v5::HostRecoveryHistoryV5> {
        // A fresh authenticated observation may disclose later pause, revoke,
        // retirement or transport-fence events. It may not silently turn this
        // original source into an observation for a successor writer epoch.
        if history.snapshot().account_id != self.account_id
            || history.snapshot().writer_epoch != self.writer_epoch
        {
            return Err(JournalError::InvalidBinding);
        }
        recovery_inventory::with_complete_source(&self.source, |tx| {
            let account = storage::read_account(tx)?;
            if account.account_id != self.account_id || account.writer_epoch != self.writer_epoch {
                return Err(JournalError::InvalidBinding);
            }
            // All exact original cells participate in the journal commitment.
            // The complete kernel validates retained witness/network/head pins,
            // every financial origin and receipt, account-use provenance, local
            // construction/reentry audit and authenticated transport history.
            // It only returns the complete V5 envelope; no import plan escapes.
            host_recovery_continuity::read_complete_continuity_v5(
                tx,
                &account,
                (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES),
                history,
            )
        })
    }
}
