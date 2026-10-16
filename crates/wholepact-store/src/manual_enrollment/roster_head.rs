//! Borrowed read-only proposed append head. This is not publication authority.
use super::*;
use wholepact_core::manual_roster_v2::HostRosterAppendBindingV2;

/// Only already-retained identity/scope metadata for an exact native review.
/// No current witness receipt, viewing key, input history or issuer is exposed.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ManualEnrollmentRosterMember {
    pub original_audit: OriginalManualEnrollmentAuditLink,
    pub identity: ManualAccountIdentity,
    pub scope: wholepact_core::manual_enrollment::BornManualScope,
}
/// No Clone, Deserialize or caller constructor. Successful publication makes
/// this pre-append owner stale; a distinct committed owner must replace it.
pub struct ManualEnrollmentRosterHead<'store> {
    store: &'store Store,
    target: ManualStoreTarget<'store>,
    agreement: StoredRecord,
    binding: HostRosterAppendBindingV2,
    projection_digest: String,
    members: Vec<ManualEnrollmentRosterMember>,
}
impl ManualEnrollmentRosterHead<'_> {
    /// Inert exact proposal to display/sign. Always check_current before use.
    pub fn binding(&self) -> &HostRosterAppendBindingV2 {
        &self.binding
    }
    pub fn members(&self) -> Result<&[ManualEnrollmentRosterMember]> {
        self.check_current()?;
        Ok(&self.members)
    }
    pub fn check_current(&self) -> Result<()> {
        let (binding, digest, members) =
            read_roster_head(self.store, &self.target, &self.agreement)?;
        if binding != self.binding || digest != self.projection_digest || members != self.members {
            return Err(StoreError::RevisionConflict);
        }
        Ok(())
    }
}
impl Store {
    pub fn manual_enrollment_roster_head<'store>(
        &'store self,
        target: &ManualStoreTarget<'_>,
        expected_agreement: &StoredRecord,
    ) -> Result<ManualEnrollmentRosterHead<'store>> {
        let (binding, projection_digest, members) =
            read_roster_head(self, target, expected_agreement)?;
        let head = ManualEnrollmentRosterHead {
            store: self,
            target: self.manual_store_target()?,
            agreement: expected_agreement.clone(),
            binding,
            projection_digest,
            members,
        };
        head.check_current()?;
        Ok(head)
    }
}
fn read_roster_head(
    store: &Store,
    target: &ManualStoreTarget<'_>,
    agreement: &StoredRecord,
) -> Result<(
    HostRosterAppendBindingV2,
    String,
    Vec<ManualEnrollmentRosterMember>,
)> {
    if !std::ptr::eq(store, target.store) {
        return Err(StoreError::RecoveryRequired);
    }
    target.check_current()?;
    let mut c = store.connection.try_lock().map_err(|error| match error {
        std::sync::TryLockError::WouldBlock => StoreError::ResourceExhausted,
        std::sync::TryLockError::Poisoned(_) => StoreError::Poisoned,
    })?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let actual =
        crate::read_record(&tx, "agreement", &agreement.id)?.ok_or(StoreError::NotFound)?;
    if actual != *agreement {
        return Err(StoreError::RevisionConflict);
    }
    if actual.revision == 0
        || actual
            .payload
            .pointer("/view/agreement/agreement_id")
            .and_then(serde_json::Value::as_str)
            != Some(agreement.id.as_str())
    {
        return Err(StoreError::RecoveryRequired);
    }
    let projection = crate::recovery::project_manual_snapshot(
        &tx,
        store
            .recovered_binding
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?,
    )?;
    let mut rows: Vec<_> = projection
        .enrollments()
        .into_iter()
        .filter(|a| a.terms().host.generation_id == target.generation_id)
        .collect();
    rows.sort_by_key(|a| a.store_sequence());
    let last = rows.last().ok_or(StoreError::RecoveryRequired)?;
    let binding = HostRosterAppendBindingV2 {
        version: 2,
        generation_id: target.generation_id.clone(),
        store_destination_identity: target.store_destination_identity.clone(),
        roster_sequence: rows.len() as u64 + 1,
        predecessor: last.roster_link()?,
    };
    binding
        .validate()
        .map_err(|_| StoreError::RecoveryRequired)?;
    let members = rows
        .into_iter()
        .map(|a| {
            Ok(ManualEnrollmentRosterMember {
                original_audit: a.original_audit_link()?,
                identity: a.terms().identity.clone(),
                scope: a.terms().scope.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let digest = projection.digest().to_owned();
    tx.commit()?;
    drop(c);
    target.check_current()?;
    Ok((binding, digest, members))
}
