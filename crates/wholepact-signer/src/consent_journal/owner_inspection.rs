//! Narrow read-only projection from the actual unlocked journal. Never a ledger
//! lookup by caller account ID, an aggregate balance, or a clearance to spend.
use super::*;
use rusqlite::OptionalExtension;
use wholepact_core::owner_inspection::*;
impl SignerConsentJournal {
    pub(crate) fn owner_inspection(
        &self,
        request: &OwnerInspectionRequest,
        session: &SignerConsentSession,
        origin: &crate::native_ui::NativeAuthorityBinding,
    ) -> Result<OwnerInspectionSnapshot> {
        if !request.validate() {
            return Err(JournalError::InvalidBinding);
        }
        let account = self.account_state()?;
        let permission = session.read_lease(&self.binding(), &account)?;
        permission.require_native_origin(origin)?;
        // The request principal identifies the receiving service client. Native
        // journal records instead belong to the owner authenticated by this
        // live session; never use a caller principal to select private records.
        let _fence = self
            .authority_fence
            .read()
            .map_err(|_| JournalError::Permission)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction()?;
        storage::check_account(&tx, &account)?;
        storage::bounded(&tx, self.capacity_limits())?;
        named_recipient_inventory::require_absent(&tx)?;
        let mut snapshot = OwnerInspectionSnapshot {
            schema_version: 1,
            request: request.clone(),
            account_id: account.account_id.clone(),
            source_principal_id: permission.principal.to_owned(),
            writer_epoch: account.writer_epoch,
            recovery_required: account.recovery_required,
            inspected_at_ms: now_ms()?,
            provenance: "native_owner_approved_local_signer_journal".into(),
            freshness: "historical_local_snapshot_no_live_witness_or_chain_observation".into(),
            authorization_allowed: false,
            balance: None,
            account_pending_exposure: None,
            account_settled_debit: None,
            account_remaining_budget: None,
            authorizations: vec![],
            sponsor_policies: vec![],
            automation_grants: vec![],
        };
        let mut q = tx.prepare(
            "SELECT authorization_id FROM signer_original_consents ORDER BY authorization_id",
        )?;
        for row in q.query_map([], |r| r.get::<_, String>(0))? {
            let id = row?;
            let original = storage::read_original(&tx, &id)?.ok_or(JournalError::InvalidBinding)?;
            let t = original.original_consent().terms();
            if t.account_id != account.account_id {
                return Err(JournalError::InvalidBinding);
            }
            if t.principal_id != permission.principal
                || t.agreement_id != request.agreement_id
                || original.enrollment().participant_id() != request.participant_id
            {
                continue;
            }
            let result_retained = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM signer_bridge_results WHERE authorization_id=?1)",
                [&id],
                |r| r.get(0),
            )?;
            let latest_settlement_record = tx.query_row("SELECT kind FROM signer_settlement_events WHERE authorization_id=?1 ORDER BY sequence DESC LIMIT 1", [&id], |r| r.get(0)).optional()?;
            snapshot.authorizations.push(AuthorizationAudit {
                authorization_id: id,
                original_consent_ref: original.original_consent().reference().into(),
                proposal_id: t.proposal_id.clone(),
                maximum_debit: wholepact_core::Amount::from_zatoshis(t.maximum_debit_zatoshis)
                    .map_err(|_| JournalError::InvalidBinding)?,
                transaction_expiry_height: t.transaction_expiry_height,
                result_retained,
                latest_settlement_record,
                automation_grant_id: t.automation.as_ref().map(|a| a.grant.grant_id.clone()),
            });
        }
        drop(q);
        let mut q = tx.prepare("SELECT policy_key FROM signer_sponsor_policy_events GROUP BY policy_key ORDER BY policy_key")?;
        for row in q.query_map([], |r| r.get::<_, String>(0))? {
            let policy = sponsor::read_current(&tx, &row?)?.ok_or(JournalError::InvalidBinding)?;
            if policy.terms.sponsor.account_id != account.account_id {
                return Err(JournalError::InvalidBinding);
            }
            if policy.principal_id != permission.principal
                || policy.terms.sponsor.participant_id != request.participant_id
                || !policy.terms.agreement_scope.contains(&request.agreement_id)
            {
                continue;
            }
            snapshot.sponsor_policies.push(SponsorAudit {
                policy_key: policy.binding.policy_key,
                version: policy.binding.version,
                terms_digest: policy.binding.terms_digest,
                status: match policy.status {
                    NativeSponsorPolicyStatus::Active => "active",
                    NativeSponsorPolicyStatus::Paused => "paused",
                    NativeSponsorPolicyStatus::Revoked => "revoked",
                }
                .into(),
                aggregate_budget: policy.terms.aggregate_budget,
                expires_at: policy.terms.expires_at,
                witness_id: policy.witness.witness_id,
                witness_policy_digest: policy.witness.policy_digest,
            });
        }
        drop(q);
        let mut q = tx.prepare("SELECT grant_id FROM signer_automation_grant_events GROUP BY grant_id ORDER BY grant_id")?;
        for row in q.query_map([], |r| r.get::<_, String>(0))? {
            let grant =
                automation::read_current(&tx, &row?)?.ok_or(JournalError::InvalidBinding)?;
            if grant.terms.account_id != account.account_id {
                return Err(JournalError::InvalidBinding);
            }
            let enrollment = storage::read_enrollment(&tx, &grant.enrollment_ref)?
                .ok_or(JournalError::InvalidBinding)?;
            if grant.principal_id != permission.principal
                || enrollment.participant_id() != request.participant_id
                || !grant.terms.agreement_ids.contains(&request.agreement_id)
            {
                continue;
            }
            let status =
                serde_json::to_value(grant.status).map_err(|_| JournalError::InvalidBinding)?;
            snapshot.automation_grants.push(AutomationAudit {
                grant_id: grant.binding.grant_id,
                application_id: grant.binding.application_id,
                revision: grant.binding.revision,
                terms_digest: grant.binding.terms_digest,
                status: status.as_str().ok_or(JournalError::InvalidBinding)?.into(),
                maximum_payment_debit: grant.terms.maximum_payment_debit,
                maximum_outstanding_debit: grant.terms.maximum_outstanding_debit,
                expires_at_ms: grant.terms.expires_at_ms,
            });
        }
        drop(q);
        if !snapshot.validate() {
            return Err(JournalError::InvalidBinding);
        }
        permission.check_current()?;
        tx.commit()?;
        Ok(snapshot)
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod tests {
    use super::*;
    use crate::consent_journal::{
        authority::fixture,
        tests::{enroll, proposal, terms},
    };
    use wholepact_storage_security::DatabaseKey;
    fn request() -> OwnerInspectionRequest {
        OwnerInspectionRequest {
            request_id: "ab".repeat(32),
            principal_id: "receiving-service-client".into(),
            agreement_id: "agreement-a".into(),
            candidate_id: "candidate-a".into(),
            participant_id: "alice".into(),
            manifest_digest: "cd".repeat(32),
        }
    }
    #[test]
    fn actual_native_session_reads_narrow_originals_without_inventing_account_totals() {
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let journal = SignerConsentJournal::create_encrypted(
            &dir.path().join("audit-source"),
            &DatabaseKey::from_bytes([74; 32]),
            "account-alice",
            1,
            false,
        )
        .unwrap();
        let origin = crate::native_ui::recovery_test_authority();
        let session = fixture::native_session(
            &journal,
            origin.binding(),
            "synthetic-owner",
            &"ab".repeat(32),
        );
        let (enrollment, manifest) = enroll(
            &journal,
            &session,
            &proposal("agreement-a", "obligation-a", "proposal-a"),
            1_000_000_000,
        );
        journal
            .record_original_consent_release(fixture::approve_spend(
                &session,
                terms(&session, &enrollment, &manifest, "authorization-a"),
            ))
            .unwrap();
        let snap = journal
            .owner_inspection(&request(), &session, &origin.binding())
            .unwrap();
        assert_eq!(snap.account_id, "account-alice");
        assert_eq!(snap.source_principal_id, "synthetic-owner");
        assert_eq!(snap.request.principal_id, "receiving-service-client");
        assert_eq!(snap.authorizations.len(), 1);
        assert_eq!(snap.authorizations[0].authorization_id, "authorization-a");
        assert_eq!(
            snap.authorizations[0].maximum_debit.as_zatoshis(),
            400_012_000
        );
        assert!(!snap.authorizations[0].result_retained);
        assert!(
            snap.balance.is_none()
                && snap.account_pending_exposure.is_none()
                && snap.account_settled_debit.is_none()
                && snap.account_remaining_budget.is_none()
        );
        assert!(snap.validate());
        let mut other = request();
        other.agreement_id = "unrelated".into();
        assert!(
            journal
                .owner_inspection(&other, &session, &origin.binding())
                .unwrap()
                .authorizations
                .is_empty()
        );
        other = request();
        other.principal_id = "other-receiving-client".into();
        let recipient_changed = journal
            .owner_inspection(&other, &session, &origin.binding())
            .unwrap();
        assert_eq!(
            recipient_changed.source_principal_id,
            snap.source_principal_id
        );
        assert_eq!(recipient_changed.authorizations, snap.authorizations);
        assert_ne!(recipient_changed.request, snap.request);
        let wrong_origin = crate::native_ui::recovery_test_authority();
        assert!(
            journal
                .owner_inspection(&request(), &session, &wrong_origin.binding())
                .is_err()
        );
        session.invalidate().unwrap();
        assert!(
            journal
                .owner_inspection(&request(), &session, &origin.binding())
                .is_err()
        );
    }
}
