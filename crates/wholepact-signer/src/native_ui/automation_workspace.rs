//! Foreground-only native automation controls. Inputs are private draft claims;
//! only a genuine exact native review can activate or change a grant.
use eframe::egui;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AutomationCommand {
    Activate,
    Pause,
    Revoke,
    Renew,
    Inspect,
    Synchronize,
    Authorize,
}
#[derive(Default)]
pub(super) struct AutomationUi {
    pub(super) grant_id: Zeroizing<String>,
    pub(super) policy_json: Zeroizing<String>,
    pub(super) terms_json: Zeroizing<String>,
    pub(super) status: Option<Zeroizing<String>>,
}
impl AutomationUi {
    pub(super) fn clear(&mut self) {
        self.grant_id.zeroize();
        self.policy_json.zeroize();
        self.terms_json.zeroize();
        self.status = None;
    }
    pub(super) fn ui(&mut self, ui: &mut egui::Ui, focused: bool) -> Option<AutomationCommand> {
        if !focused {
            return None;
        }
        let mut action = None;
        egui::CollapsingHeader::new("Foreground bounded automation").show(ui, |ui| {
            ui.label("One authenticated enrolled local application and account. Activation grants exact bounded signing only. Each request still needs a separate native witness privacy decision. Export and dispatch require their own approvals.");
            ui.label("This foreground profile also binds the witness grant to the currently accepted proposal/candidate. A different candidate requires explicit grant renewal and a new witness review, even within the same agreement and payment limits.");
            ui.label("Grant ID (pause, revoke, renewal, status and authorization)");
            ui.add(egui::TextEdit::singleline(&mut *self.grant_id).char_limit(128));
            ui.label("Exact account policy JSON");
            ui.add(egui::TextEdit::multiline(&mut *self.policy_json).char_limit(32768).desired_rows(3));
            ui.label("Exact grant terms JSON. Specify explicit agreement and verified recipient fingerprints, fee, debit, evidence freshness and expiry limits.");
            ui.add(egui::TextEdit::multiline(&mut *self.terms_json).char_limit(65536).desired_rows(4));
            ui.label("The independent witness account lifetime debit includes settled plus pending authorization. Account and grant outstanding-debit limits are enforced separately; settlement never replenishes the lifetime budget.");
            for (label, command) in [
                ("Review explicit activation", AutomationCommand::Activate),
                ("Review pause", AutomationCommand::Pause),
                ("Review permanent revoke", AutomationCommand::Revoke),
                ("Review fresh renewal", AutomationCommand::Renew),
                ("Inspect retained grant and attempts", AutomationCommand::Inspect),
                ("Review synchronization of retained revision", AutomationCommand::Synchronize),
                ("Verify incoming request under this grant", AutomationCommand::Authorize),
            ] {
                if ui.button(label).clicked_by(egui::PointerButton::Primary) { action = Some(command); }
            }
            ui.label("Allowed: the exact enrolled application, account, agreement, recipients and current artifact within all limits. Rejected: wrong peer or scope, stale evidence/session, changed artifact, exhausted budget, paused/revoked/expired grant. Uncertain attempts retain exposure and must use original-result redelivery.");
            ui.label("Status below is retained local evidence, not permission to sign. Eligibility also requires the matching live witness revision, current native session and complete history.");
            if let Some(status) = &self.status { ui.label(super::state::inert_text(status)); }
        });
        action
    }
}

use super::{
    NativeAuthority, NativeAuthorityBinding, NativeDecision,
    witness_workspace::NativeWitnessWorkspace,
};
use crate::{Error, Result, consent_journal::NativeAutomationGrantRecord};
use std::{sync::Arc, time::Instant};

/// A distinct exact privacy/control review. Local grant consent never authorizes
/// transmitting its linkage to the independent owner-control witness.
pub(super) struct PreparedGrantSynchronization {
    request: wholepact_authority::OwnerControlRequest,
    owner: Arc<NativeWitnessWorkspace>,
    source: NativeAuthorityBinding,
    digest: String,
    display: Zeroizing<String>,
    created: Instant,
    already_synchronized: bool,
}
impl PreparedGrantSynchronization {
    pub(super) fn prepare(
        record: NativeAutomationGrantRecord,
        recipient_scope_digest: Option<String>,
        owner: Arc<NativeWitnessWorkspace>,
        source: NativeAuthorityBinding,
    ) -> Result<Self> {
        source.check_current()?;
        owner.check_current()?;
        let history = owner
            .client()
            .reconcile_history()
            .map_err(|_| Error::Unavailable)?;
        let snapshot = history.snapshot();
        if snapshot.account_id != record.terms.account_id
            || snapshot.writer_epoch != record.terms.writer_epoch
            || snapshot.writer_certificate_digest == owner.writer_certificate_digest()
            || snapshot.witness_id != record.witness.witness_id
            || owner.disclosure().policy_digest != record.witness.policy_digest
        {
            return Err(Error::Authentication);
        }
        let grant =
            validate_grant_for_witness(&record, &history, recipient_scope_digest.as_deref())?;
        let account_policy = wholepact_authority::WitnessAutomationAccountPolicy {
            policy_id: record.policy.policy_id.clone(),
            writer_epoch: record.policy.writer_epoch,
            maximum_outstanding_debit_zatoshis: record
                .policy
                .maximum_outstanding_debit
                .as_zatoshis(),
            valid_from_ms: record.policy.valid_from_ms,
            expires_at_ms: record.policy.expires_at_ms,
        };
        let already_synchronized = history.automation_grant(&record.binding.grant_id)
            == Some(&grant)
            && (record.status != wholepact_authority::AutomationGrantStatus::Active
                || history.automation_account_policy() == Some(&account_policy));
        let request = wholepact_authority::OwnerControlRequest {
            operation_id: hex::encode(crate::vault::random::<32>()?),
            account_id: snapshot.account_id.clone(),
            network_profile_id: snapshot.network_profile_id.clone(),
            expected_head: snapshot.head.clone(),
            writer_epoch: snapshot.writer_epoch,
            control: wholepact_authority::OwnerControl::SetAutomationGrant {
                grant,
                account_policy,
            },
        };
        let descriptor = owner.disclosure();
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-automation-witness-control:v1",
            &(&request, &descriptor),
        )
        .map_err(|_| Error::InvalidData)?;
        let display = Zeroizing::new(format!(
            "SEPARATE AUTOMATION WITNESS DISCLOSURE AND CONTROL\nWitness: {}\nEndpoint: {}\nPinned certificate: {}\nExact control: {}\n\nThis transmits the displayed account/application/enrollment/agreement linkage, recipient-scope commitment, grant limits, revision and status to this independently selected witness. No spending keys, viewing keys or transaction bytes are transmitted. Pause/revoke fences NEW automatic admission; an exact already-admitted operation may drain and prior exposure remains. Local consent is already retained; a failed or uncertain synchronization does not activate a mismatched grant.\nReview digest: {}",
            descriptor.witness_id,
            descriptor.endpoint,
            descriptor.pinned_server_certificate_digest,
            serde_json::to_string_pretty(&request).map_err(|_| Error::InvalidData)?,
            digest
        ));
        Ok(Self {
            request,
            owner,
            source,
            digest,
            display,
            created: Instant::now(),
            already_synchronized,
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn display(&self) -> Result<String> {
        self.source.check_current()?;
        Ok(self.display.to_string())
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
    ) -> Result<ApprovedGrantSynchronization> {
        self.source.check_current()?;
        if self.created.elapsed().as_secs() >= 120
            || decision.binding() != &self.source
            || authority.binding() != self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ApprovedGrantSynchronization(self))
    }
}
pub(super) struct ApprovedGrantSynchronization(PreparedGrantSynchronization);
impl ApprovedGrantSynchronization {
    pub(super) fn run(self) -> Result<()> {
        self.0.source.check_current()?;
        self.0.owner.check_current()?;
        if self.0.created.elapsed().as_secs() >= 120 {
            return Err(Error::Locked);
        }
        let _publication = self.0.source.publication_lease()?;
        if self.0.already_synchronized {
            return Ok(());
        }
        self.0
            .owner
            .client()
            .control(self.0.request)
            .map_err(|_| Error::Uncertain)?;
        Ok(())
    }
}

/// Precommit validation against the immutable policy from complete authenticated
/// witness history. Prevents approving a revision the witness can never accept.
pub(super) fn validate_grant_for_witness(
    record: &NativeAutomationGrantRecord,
    history: &wholepact_authority::ReconciledAuthorityHistory,
    recipient_scope_digest: Option<&str>,
) -> Result<wholepact_authority::WitnessAutomationGrant> {
    let recipient_scope_digests =
        if record.status == wholepact_authority::AutomationGrantStatus::Active {
            vec![
                recipient_scope_digest
                    .ok_or(Error::ReviewMismatch)?
                    .to_owned(),
            ]
        } else {
            let original = history
                .automation_grant(&record.binding.grant_id)
                .ok_or(Error::ReviewMismatch)?;
            if original.enrollment_ref != record.enrollment_ref
                || original.binding.application_id != record.binding.application_id
                || original.writer_epoch != record.terms.writer_epoch
            {
                return Err(Error::Authentication);
            }
            original.recipient_scope_digests.clone()
        };
    let grant = wholepact_authority::WitnessAutomationGrant {
        binding: record.binding.clone(),
        account_policy_id: record.policy.policy_id.clone(),
        writer_epoch: record.terms.writer_epoch,
        enrollment_ref: record.enrollment_ref.clone(),
        agreement_ids: record.terms.agreement_ids.clone(),
        recipient_scope_digests,
        maximum_payment_debit_zatoshis: record.terms.maximum_payment_debit.as_zatoshis(),
        maximum_payment_fee_zatoshis: record.terms.maximum_payment_fee.as_zatoshis(),
        maximum_outstanding_debit_zatoshis: record.terms.maximum_outstanding_debit.as_zatoshis(),
        maximum_authorization_lifetime_ms: record.terms.maximum_authorization_lifetime_ms,
        valid_from_ms: record.terms.valid_from_ms,
        expires_at_ms: record.terms.expires_at_ms,
        status: record.status,
    };
    grant.validate().map_err(|_| Error::InvalidData)?;

    let policy = history.account_policy();
    let snapshot = history.snapshot();
    if policy.account_id != record.terms.account_id
        || policy.network_profile_id != record.terms.network_profile
        || policy.witness_id != record.witness.witness_id
        || snapshot.writer_epoch != record.terms.writer_epoch
    {
        return Err(Error::Authentication);
    }
    let account_policy = wholepact_authority::WitnessAutomationAccountPolicy {
        policy_id: record.policy.policy_id.clone(),
        writer_epoch: record.policy.writer_epoch,
        maximum_outstanding_debit_zatoshis: record.policy.maximum_outstanding_debit.as_zatoshis(),
        valid_from_ms: record.policy.valid_from_ms,
        expires_at_ms: record.policy.expires_at_ms,
    };
    if let Some(existing) = history.automation_account_policy_by_id(&account_policy.policy_id) {
        if existing != &account_policy
            || (record.status == wholepact_authority::AutomationGrantStatus::Active
                && history.automation_account_policy() != Some(&account_policy))
        {
            return Err(Error::Verification);
        }
    }
    grant
        .validate_account_bounds(&account_policy, policy)
        .map_err(|_| Error::Verification)?;
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_automation_inputs_are_cleared_together() {
        let mut ui = AutomationUi::default();
        ui.grant_id.push_str("synthetic-grant");
        ui.policy_json.push_str("synthetic-policy");
        ui.terms_json.push_str("synthetic-terms");
        ui.status = Some(Zeroizing::new("synthetic-retained-status".into()));
        ui.clear();
        assert!(ui.grant_id.is_empty() && ui.policy_json.is_empty() && ui.terms_json.is_empty());
        assert!(ui.status.is_none());
    }
}
