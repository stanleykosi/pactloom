//! Native exact record creation permission. Account identity comes from a live
//! authenticated signer history lease; typed text or coordinator roles do not
//! establish ownership. This permission never exports receipt fields.
use super::*;
use wholepact_signer::authority_bridge::ipc::OriginalHistoryLease;

pub(crate) struct NativeRecordRetentionAuthority<'a> {
    native: Arc<Authority>,
    approved: ParticipantRecordScope,
    history: &'a OriginalHistoryLease<'a>,
    expires: u64,
}
impl Authority {
    pub(crate) fn approve_record_retention<'a>(
        self: &Arc<Self>,
        scope: ParticipantRecordScope,
        history: &'a OriginalHistoryLease<'a>,
    ) -> Result<NativeRecordRetentionAuthority<'a>> {
        let grant = NativeRecordRetentionAuthority {
            native: self.clone(),
            approved: scope,
            history,
            expires: now()?.saturating_add(60),
        };
        grant.check()?;
        self.terminal.confirm(&format!(
            "Retain this exact PRIVATE participant record from original signer consent, authenticated authorizations and existing protected transaction bytes?\nScope: {:#?}\nOriginal signer consent: {}\nOriginal authorization: {}\nThis preserves outstanding exposure. It is not chain settlement, complete account history, a new signature or permission to export receipt fields. Expiry Unix: {}",
            grant.approved, history.evidence().consent.reference(), history.evidence().consent.terms().authorization_id, grant.expires
        ))?;
        grant.check()?;
        Ok(grant)
    }
}
impl NativeRecordRetentionAuthority<'_> {
    fn check(&self) -> Result<()> {
        self.native.principal(&self.approved.principal_id)?;
        self.history
            .check_current()
            .map_err(|_| Error::Permission)?;
        let e = self.history.evidence();
        let t = e.consent.terms();
        if self.expires <= now()?
            || self.approved.store != self.native.store
            || self.approved.profile_id != self.native.profile
            || self.approved.action != ParticipantRecordAction::Retain
            || self.approved.principal_id != t.principal_id
            || self.approved.agreement_id != t.agreement_id
            || self.approved.account_id != t.account_id
            || self.approved.participant_id != e.enrollment.participant_id()
            || e.retained_result.is_none()
        {
            return Err(Error::Permission);
        }
        Ok(())
    }
}
struct NativeRecordRetentionLease<'a> {
    authority: &'a NativeRecordRetentionAuthority<'a>,
    held: Held,
    expires: String,
}
impl ParticipantRecordAuthority for NativeRecordRetentionAuthority<'_> {
    fn acquire<'a>(
        &'a self,
        scope: &ParticipantRecordScope,
        _: &ObservationWindow,
    ) -> std::result::Result<Box<dyn ParticipantRecordLease + 'a>, ApiError> {
        if scope != &self.approved {
            return Err(denied());
        }
        api(self.check())?;
        let held = api(self.native.fence.acquire(self.expires))?;
        api(self.check())?;
        let expires = api(Timestamp::from_unix_seconds(self.expires as i64).map_err(Error::from))?
            .as_str()
            .to_owned();
        Ok(Box::new(NativeRecordRetentionLease {
            authority: self,
            held,
            expires,
        }))
    }
}
impl ParticipantRecordLease for NativeRecordRetentionLease<'_> {
    fn scope(&self) -> &ParticipantRecordScope {
        &self.authority.approved
    }
    fn expires_at(&self) -> &str {
        &self.expires
    }
    fn check_current(&self) -> std::result::Result<(), ApiError> {
        api(self.held.check())?;
        api(self.authority.check())
    }
}
