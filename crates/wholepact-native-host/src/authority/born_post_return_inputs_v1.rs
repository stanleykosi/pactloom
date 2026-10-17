//! Fresh native protected-wallet read approval, never a construction renewal.
use super::{Authority, Held};
use crate::{Error, Result, now, terminal::historical::HistoricalApproval};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wholepact_wallet::wallet::protected_sync::born_post_return_inputs_v1::BornPostReturnWalletScopeV1;

pub(crate) struct BornPostReturnNativeReadV1 {
    held: Held,
    approval: HistoricalApproval,
    principal: String,
    deadline: Instant,
    expires_at_ms: u64,
    issued_at_ms: u64,
    review_digest: String,
}
impl BornPostReturnNativeReadV1 {
    /// Only trusted private Host composition calls this, after deriving every
    /// disclosure field from actual checkpoint/final-transaction/file owners.
    pub(crate) fn review(
        authority: &Authority,
        prior: &HistoricalApproval,
        principal: &str,
        scopes: &[BornPostReturnWalletScopeV1],
        check: impl Fn() -> Result<()>,
    ) -> Result<Self> {
        if scopes.is_empty() || scopes.len() > 8 {
            return Err(Error::Invalid);
        }
        for scope in scopes {
            scope.validate().map_err(|_| Error::Invalid)?;
        }
        authority.check_financial_principal_fail_fast(principal)?;
        check()?;
        let review_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-born-post-return-read:v1",
            &scopes,
        )
        .map_err(|_| Error::Invalid)?;
        let approval=authority.terminal.approve_historical_reviewed(prior,&format!(
            "Approve one fresh post-return protected-wallet observation of these EXACT original inputs and final signed transaction. This is NOT renewed construction, selection, signature release, replacement, or broadcast approval. Reopen only the named already registered encrypted wallet files. Contact only the named original TLS provider using the exact disclosed captured direct or existing credential-free HTTP CONNECT route and request/cache/freshness policy: IP, timing, public block heights and public tree queries are visible; FVKs, input IDs and nullifiers are NEVER sent. Scan at most the declared public block range/runtime and check locally held unspent notes against their original anchor/witness and exact full FVK. Scan progress may persist locally. These private account/input/final-transaction links remain sensitive indefinitely. A single provider does NOT establish independent consensus, a global mempool absence, or irreversible unspentness. File replacement, restoration, rollback, revocation, deadline or inconsistent tips refuses dispatch and preserves all authorization exposure.\nExact current read review: {}\nExact scopes: {}",review_digest,serde_json::to_string_pretty(scopes)?))?;
        check()?;
        authority.check_financial_principal_fail_fast(principal)?;
        let issued_at_ms = wall_ms()?;
        let expires_at_ms = scopes
            .iter()
            .map(|s| s.native_observation_expires_at_ms)
            .min()
            .ok_or(Error::Invalid)?;
        if expires_at_ms <= issued_at_ms || expires_at_ms - issued_at_ms > 60_000 {
            return Err(Error::Permission);
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(expires_at_ms - issued_at_ms))
            .ok_or(Error::Invalid)?
            .min(approval.deadline())
            .min(prior.deadline());
        let held = authority
            .fence
            .acquire(now()?.checked_add(60).ok_or(Error::Invalid)?)?;
        let result = Self {
            held,
            approval,
            principal: principal.to_owned(),
            deadline,
            expires_at_ms,
            issued_at_ms,
            review_digest,
        };
        result.check(authority)?;
        Ok(result)
    }
    pub(crate) fn check(&self, authority: &Authority) -> Result<()> {
        self.held.check()?;
        self.approval.check()?;
        authority.check_financial_principal_fail_fast(&self.principal)?;
        let now = wall_ms()?;
        if Instant::now() >= self.deadline || now < self.issued_at_ms || now >= self.expires_at_ms {
            return Err(Error::Permission);
        }
        Ok(())
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn review_digest(&self) -> &str {
        &self.review_digest
    }
}
pub(crate) fn wall_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Permission)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Invalid)
}
