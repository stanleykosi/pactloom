//! Concrete maintained-wallet recovery inspection. Complete compact-block scans
//! cover known Orchard AND Ironwood balances, not just selected spendable notes.
//! This is deliberately not an empty-account or authorization capability: the
//! existing importer accepts a claimed birthday and does not ingest a complete
//! pending/full-transaction feed or signer-wide authorization history.
use super::*;
#[path = "recovery_scan_coverage.rs"]
mod coverage;
pub use coverage::{RetirementCoverageReport, RetirementEvidenceGap};
use zcash_client_backend::data_api::{Balance, scanning::ScanPriority};

/// Separate local native read approval; contribution-selection consent is not
/// automatically permission to reveal every known pool balance.
pub trait LocalRecoveryReadAccess {
    fn permits_recovery_read(&self, account: AccountUuid, provider: &BackendIdentity) -> bool;
}
#[derive(Debug, thiserror::Error)]
pub enum RecoveryScanError {
    #[error("complete recovery balance read is not approved")]
    AccessDenied,
    #[error("wallet contains unsupported or unknown account key components")]
    UnsupportedAccountComponents,
    #[error("account scan is incomplete, stale or lacks a complete summary")]
    IncompleteScan,
    #[error("known funds remain in this account")]
    KnownFundsRemain,
    #[error(
        "complete account retirement needs authenticated birthday, pending transactions, current canonical node and writer authorization history"
    )]
    AdditionalEvidenceRequired,
    #[error(transparent)]
    Sync(#[from] SyncError),
    #[error(transparent)]
    Wallet(#[from] WalletError),
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KnownPoolBalance {
    pub total_zatoshis: u64,
    pub spendable_zatoshis: u64,
    pub locked_zatoshis: u64,
    pub pending_change_zatoshis: u64,
    pub pending_spendability_zatoshis: u64,
    /// Kept separately rather than guessing whether the upstream implementation
    /// includes it in another category. Any nonzero amount blocks emptiness.
    pub uneconomic_zatoshis: u64,
}
impl From<&Balance> for KnownPoolBalance {
    fn from(b: &Balance) -> Self {
        Self {
            total_zatoshis: b.total().into_u64(),
            spendable_zatoshis: b.spendable_value().into_u64(),
            locked_zatoshis: b.locked_value().into_u64(),
            pending_change_zatoshis: b.change_pending_confirmation().into_u64(),
            pending_spendability_zatoshis: b.value_pending_spendability().into_u64(),
            uneconomic_zatoshis: b.uneconomic_value().into_u64(),
        }
    }
}
impl KnownPoolBalance {
    fn has_funds(&self) -> bool {
        self.total_zatoshis != 0
            || self.spendable_zatoshis != 0
            || self.locked_zatoshis != 0
            || self.pending_change_zatoshis != 0
            || self.pending_spendability_zatoshis != 0
            || self.uneconomic_zatoshis != 0
    }
}
/// Opaque current-generation observation; no Deserialize, Clone or public
/// constructor. Pool values remain sensitive local account information.
pub struct AccountRecoveryScan {
    guard: WalletObservationGuard,
    account: AccountUuid,
    birthday_height: u32,
    tip_height: u32,
    outstanding_transaction_data_requests: u32,
    orchard: KnownPoolBalance,
    ironwood: KnownPoolBalance,
}
impl std::fmt::Debug for AccountRecoveryScan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "AccountRecoveryScan { private_balances: [REDACTED], completion_evidence: INCOMPLETE }",
        )
    }
}
impl AccountRecoveryScan {
    pub fn check_current(&self) -> Result<(), RecoveryScanError> {
        self.guard.check_current()?;
        Ok(())
    }
    pub fn account_uuid(&self) -> AccountUuid {
        self.account
    }
    pub fn claimed_birthday_height(&self) -> u32 {
        self.birthday_height
    }
    pub fn observed_tip_height(&self) -> u32 {
        self.tip_height
    }
    pub fn known_pool_balances(
        &self,
    ) -> Result<(KnownPoolBalance, KnownPoolBalance), RecoveryScanError> {
        self.check_current()?;
        Ok((self.orchard, self.ironwood))
    }
    /// Diagnostic from this current maintained-wallet read. This never
    /// authenticates the original birthday or complete pending/release history.
    pub fn retirement_coverage(&self) -> Result<RetirementCoverageReport, RecoveryScanError> {
        self.check_current()?;
        Ok(coverage::report(
            self.birthday_height,
            self.tip_height,
            self.outstanding_transaction_data_requests,
            self.orchard,
            self.ironwood,
        ))
    }
    /// Diagnostic only. No successful empty-account result exists until the
    /// missing independently authenticated evidence has an implemented issuer.
    pub fn require_retirement_completion(&self) -> Result<(), RecoveryScanError> {
        self.check_current()?;
        completion_gate(self.orchard, self.ironwood)
    }
}
fn completion_gate(
    orchard: KnownPoolBalance,
    ironwood: KnownPoolBalance,
) -> Result<(), RecoveryScanError> {
    if orchard.has_funds() || ironwood.has_funds() {
        Err(RecoveryScanError::KnownFundsRemain)
    } else {
        Err(RecoveryScanError::AdditionalEvidenceRequired)
    }
}

impl ProtectedWalletSync {
    /// Makes no network request and imports no key. The caller must separately
    /// acquire a signer-authenticated FVK and keep that authority current. This
    /// method establishes local wallet matching, not that caller association.
    pub fn inspect_account_recovery(
        &self,
        access: &impl LocalRecoveryReadAccess,
        expected_fvk: &FullViewingKey,
    ) -> Result<AccountRecoveryScan, RecoveryScanError> {
        if !access.permits_recovery_read(self.account, self.source.identity()) {
            return Err(RecoveryScanError::AccessDenied);
        }
        self.verify_account_fvk(expected_fvk)?;
        let observation = self
            .accepted
            .as_ref()
            .ok_or(RecoveryScanError::IncompleteScan)?;
        let guard = WalletObservationGuard {
            monotonic_started: observation.monotonic_started,
            observation: observation.chain.clone(),
            generation: Arc::downgrade(&self.generation),
        };
        guard.check_current()?;
        let (birthday_height, orchard, ironwood) = read_known_pools(
            &self.wallet,
            self.account,
            expected_fvk,
            &observation.selection,
            self.minimum_confirmations,
        )?;
        // The maintained API materializes its request vector before this cap.
        // This is an acceptance/output bound, not a preemptible database-read bound.
        let outstanding_transaction_data_requests = self
            .wallet
            .db
            .transaction_data_requests()
            .map_err(|_| WalletError::Storage)?
            .len();
        if outstanding_transaction_data_requests > 4096 {
            return Err(RecoveryScanError::IncompleteScan);
        }
        let outstanding_transaction_data_requests =
            u32::try_from(outstanding_transaction_data_requests)
                .map_err(|_| RecoveryScanError::IncompleteScan)?;
        guard.check_current()?;
        if !access.permits_recovery_read(self.account, self.source.identity()) {
            return Err(RecoveryScanError::AccessDenied);
        }
        Ok(AccountRecoveryScan {
            guard,
            account: self.account,
            birthday_height,
            tip_height: observation.selection.tip_height,
            outstanding_transaction_data_requests,
            orchard,
            ironwood,
        })
    }
}
fn read_known_pools(
    wallet: &DedicatedTestnetWallet,
    account: AccountUuid,
    expected_fvk: &FullViewingKey,
    context: &SelectionContext,
    confirmations: NonZeroU32,
) -> Result<(u32, KnownPoolBalance, KnownPoolBalance), RecoveryScanError> {
    let storage = |_| WalletError::Storage;
    let local = wallet
        .db
        .get_account(account)
        .map_err(storage)?
        .ok_or(WalletError::AccountScope)?;
    let key = local
        .ufvk()
        .ok_or(RecoveryScanError::UnsupportedAccountComponents)?;
    // Exact maintained canonical encoding rejects hidden/unknown, Sapling and
    // transparent components, including those not compiled into key features.
    let only_orchard = unified::Ufvk::try_from_items(
        zcash_protocol::address::Revision::R0,
        vec![unified::Uitem::Data(unified::Fvk::Orchard(
            expected_fvk.to_bytes(),
        ))],
    )
    .map_err(|_| RecoveryScanError::UnsupportedAccountComponents)?
    .encode(&NetworkType::Test);
    if key
        .encode(&TEST_NETWORK)
        .map_err(|_| RecoveryScanError::UnsupportedAccountComponents)?
        != only_orchard
    {
        return Err(RecoveryScanError::UnsupportedAccountComponents);
    }
    let birthday = wallet.db.get_account_birthday(account).map_err(storage)?;
    let summary = wallet
        .db
        .get_wallet_summary(ConfirmationsPolicy::new_symmetrical(confirmations))
        .map_err(storage)?
        .ok_or(RecoveryScanError::IncompleteScan)?;
    if !summary.is_synced()
        || u32::from(summary.chain_tip_height()) != context.tip_height
        || u32::from(summary.fully_scanned_height()) != context.tip_height
        || wallet.db.chain_height().map_err(storage)? != Some(context.tip_height.into())
        || wallet
            .db
            .get_block_hash(context.tip_height.into())
            .map_err(storage)?
            .map(|h| h.0)
            != Some(context.tip_hash_protocol)
        || wallet
            .db
            .get_wallet_recover_until()
            .map_err(storage)?
            .is_some_and(|h| u32::from(h) > context.tip_height)
        || wallet
            .db
            .suggest_scan_ranges()
            .map_err(storage)?
            .iter()
            .any(|r| {
                r.priority() > ScanPriority::Scanned
                    && r.block_range().start <= context.tip_height.into()
                    && r.block_range().end > birthday
            })
    {
        return Err(RecoveryScanError::IncompleteScan);
    }
    if summary.account_balances().len() != 1 {
        return Err(WalletError::AccountScope.into());
    }
    let balances = summary
        .account_balances()
        .get(&account)
        .ok_or(RecoveryScanError::IncompleteScan)?;
    // Defensive even if the canonical UFVK contains no such component.
    if balances.sapling_balance().total().into_u64() != 0
        || balances.unshielded_balance().total().into_u64() != 0
    {
        return Err(RecoveryScanError::UnsupportedAccountComponents);
    }
    Ok((
        u32::from(birthday),
        balances.orchard_balance().into(),
        balances.ironwood_balance().into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_scan_never_turns_zero_or_uneconomic_balance_into_completion() {
        let zero = KnownPoolBalance::from(&Balance::ZERO);
        assert!(matches!(
            completion_gate(zero, zero),
            Err(RecoveryScanError::AdditionalEvidenceRequired)
        ));
        let mut b = Balance::ZERO;
        b.add_pending_spendable_value(Zatoshis::from_u64(7).unwrap())
            .unwrap();
        assert!(matches!(
            completion_gate((&b).into(), zero),
            Err(RecoveryScanError::KnownFundsRemain)
        ));
        let mut b = Balance::ZERO;
        b.add_uneconomic_value(Zatoshis::from_u64(1).unwrap())
            .unwrap();
        assert!(matches!(
            completion_gate(zero, (&b).into()),
            Err(RecoveryScanError::KnownFundsRemain)
        ));
    }
    #[test]
    fn recovery_scan_uses_actual_maintained_balances_and_rejects_wrong_tip_and_key() {
        let (wallet, account, fvk, context, _blocks) =
            super::super::super::qualification::synthetic_wallet();
        let result = read_known_pools(
            &wallet,
            account,
            &fvk,
            &context,
            NonZeroU32::new(1).unwrap(),
        )
        .unwrap();
        assert!(result.2.total_zatoshis > 0);
        let known_requests = wallet.db.transaction_data_requests().unwrap().len();
        let diagnostic = coverage::report(
            result.0,
            context.tip_height,
            u32::try_from(known_requests).unwrap(),
            result.1,
            result.2,
        );
        let encoded = serde_json::to_value(diagnostic).unwrap();
        assert_eq!(
            encoded["outstanding_wallet_transaction_data_requests"],
            known_requests
        );
        assert_eq!(encoded["claimed_import_birthday_height"], result.0);
        assert_eq!(
            encoded["local_fully_scanned_tip_height"],
            context.tip_height
        );
        assert_eq!(encoded["known_funds_observed"], true);
        assert_eq!(encoded["retirement_completion"], "unavailable");
        assert!(matches!(
            completion_gate(result.1, result.2),
            Err(RecoveryScanError::KnownFundsRemain)
        ));
        let mut wrong = context.clone();
        wrong.tip_hash_protocol = [0; 32];
        assert!(
            read_known_pools(&wallet, account, &fvk, &wrong, NonZeroU32::new(1).unwrap()).is_err()
        );
        let wrong_key =
            FullViewingKey::from(&orchard::keys::SpendingKey::from_bytes([72; 32]).unwrap());
        assert!(
            read_known_pools(
                &wallet,
                account,
                &wrong_key,
                &context,
                NonZeroU32::new(1).unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn recovery_scan_rejects_unknown_key_components_and_unscanned_account() {
        let (_, _, fvk, context, _) = super::super::super::qualification::synthetic_wallet();
        let birthday = || {
            AccountBirthday::from_parts(
                zcash_client_backend::data_api::chain::ChainState::empty(
                    (context.tip_height - 1).into(),
                    zcash_primitives::block::BlockHash([50; 32]),
                ),
                None,
            )
        };
        let mut wallet = DedicatedTestnetWallet::from_connection(
            rusqlite::Connection::open_in_memory().unwrap(),
        )
        .unwrap();
        let account = wallet.import_dedicated_fvk(&fvk, birthday()).unwrap();
        assert!(read_known_pools(&wallet, account, &fvk, &context, NonZeroU32::MIN).is_err());
        let mut wallet = DedicatedTestnetWallet::from_connection(
            rusqlite::Connection::open_in_memory().unwrap(),
        )
        .unwrap();
        let encoded = unified::Ufvk::try_from_items(
            zcash_protocol::address::Revision::R0,
            vec![
                unified::Uitem::Data(unified::Fvk::Orchard(fvk.to_bytes())),
                unified::Uitem::Data(unified::Fvk::Unknown {
                    typecode: 0x1234,
                    data: vec![7; 32],
                }),
            ],
        )
        .unwrap()
        .encode(&NetworkType::Test);
        let key = UnifiedFullViewingKey::decode(&TEST_NETWORK, &encoded).unwrap();
        let account = wallet
            .db
            .import_account_ufvk(
                "synthetic-unsupported-component",
                &key,
                &birthday(),
                AccountPurpose::Spending { derivation: None },
                None,
            )
            .unwrap()
            .id();
        assert!(matches!(
            read_known_pools(&wallet, account, &fvk, &context, NonZeroU32::MIN),
            Err(RecoveryScanError::UnsupportedAccountComponents)
        ));
    }
}
