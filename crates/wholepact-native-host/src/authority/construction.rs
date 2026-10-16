//! Source-bound native construction consent. Each participant's real signer
//! controls viewing disclosure; native consent only selects the local operation.
use super::*;
use wholepact_proof_jobs::{CheckpointScope, LocalAction, LocalProofConsent};
use wholepact_signer::authority_bridge::preconstruction_ipc::SignerPreconstructionLease;
use wholepact_wallet::wallet::{
    AccountUuid,
    protected_sync::{BackendIdentity, LocalWalletAccess, WalletAccessPurpose},
};

pub(crate) struct ConstructionConsent<'a> {
    leases: &'a [SignerPreconstructionLease<'a>],
    principal: String,
    terminal: Terminal,
    held: Held,
    approved: Mutex<Vec<(CheckpointScope, LocalAction)>>,
}
impl Authority {
    pub(crate) fn construction_consent<'a>(
        &self,
        principal: &str,
        leases: &'a [SignerPreconstructionLease<'a>],
    ) -> Result<ConstructionConsent<'a>> {
        self.principal(principal)?;
        if leases.is_empty() || leases.len() > 8 {
            return Err(Error::Invalid);
        }
        for lease in leases {
            lease.check_current().map_err(|_| Error::Permission)?;
        }
        Ok(ConstructionConsent {
            leases,
            principal: principal.into(),
            terminal: self.terminal.clone(),
            held: self
                .fence
                .acquire(now()?.checked_add(900).ok_or(Error::Invalid)?)?,
            approved: Mutex::new(Vec::new()),
        })
    }
}
impl ConstructionConsent<'_> {
    pub(crate) fn check(&self) -> Result<()> {
        self.held.check()?;
        for lease in self.leases {
            lease.check_current().map_err(|_| Error::Permission)?;
        }
        Ok(())
    }
}
impl LocalProofConsent for ConstructionConsent<'_> {
    fn permits(&self, scope: &CheckpointScope, action: LocalAction) -> bool {
        if !matches!(
            action,
            LocalAction::InspectStatus | LocalAction::RetainPrivateWitnesses
        ) || self.check().is_err()
            || scope.principal_id != self.principal
            || scope.account_ids.len() != self.leases.len()
        {
            return false;
        }
        let accounts: std::collections::BTreeSet<_> = scope.account_ids.iter().collect();
        if accounts.len() != self.leases.len() {
            return false;
        }
        for lease in self.leases {
            let approved = lease.scope();
            if !accounts.contains(&approved.account_id)
                || approved.principal_id != scope.principal_id
                || approved.proposal.proposal_id != scope.candidate_id
                || lease.manifest_digest() != scope.manifest_digest
                || approved.operator_name != scope.local_operator
                || approved.purpose != scope.purpose
                || approved.retention_policy != scope.retention_policy
                || approved
                    .reviewer_account_ids
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    != accounts
            {
                return false;
            }
        }
        let Ok(mut approved) = self.approved.lock() else {
            return false;
        };
        // Once a scope has been approved, no alternative randomized artifact may
        // reuse this command's consent even if it has the same manifest.
        if approved.iter().any(|(prior, _)| prior != scope) {
            return false;
        }
        if !approved
            .iter()
            .any(|(prior, a)| prior == scope && *a == action)
        {
            let Ok(detail) = serde_json::to_string_pretty(scope) else {
                return false;
            };
            if self.terminal.confirm(&format!("Allow {action:?} for these exact newly constructed private artifacts?\n{detail}\nEvery selected owner has separately approved dedicated viewing/witness disclosure to this exact local destination. The encrypted proof journal retains viewing keys, notes and witnesses. No remote export, signature or transaction submission is authorized.")).is_err() || self.check().is_err() { return false; }
            approved.push((scope.clone(), action));
        }
        self.check().is_ok()
    }
}

pub(crate) struct ConstructionWalletAccess<'a, 'b> {
    pub(crate) account: AccountUuid,
    pub(crate) lease: &'a SignerPreconstructionLease<'b>,
    pub(crate) consent: &'a ConstructionConsent<'b>,
}
impl LocalWalletAccess for ConstructionWalletAccess<'_, '_> {
    fn permits(
        &self,
        account: AccountUuid,
        provider: &BackendIdentity,
        _purpose: WalletAccessPurpose,
    ) -> bool {
        let scope = self.lease.scope();
        account == self.account
            && provider.source_id == scope.provider.source_id
            && provider.endpoint == scope.provider.endpoint
            && provider.trust_profile == scope.provider.trust_profile
            && self.lease.check_current().is_ok()
            && self.consent.check().is_ok()
    }
}
