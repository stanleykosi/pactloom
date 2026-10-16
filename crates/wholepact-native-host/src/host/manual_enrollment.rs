//! Private Host conjunction for one audit-only enrollment. Existing recovered
//! financial gates stay unchanged. No public constructor, DTO-to-authority
//! conversion, caller callback or financial exception is added. The separate
//! command module owns the explicit initial request/export/acquire sequence.
mod command;
use super::*;
use crate::{
    recovery_generation::manual_target::ManualCommittedTarget,
    terminal::{PublicationApproval, historical::HistoricalApproval},
};
pub(in crate::host) use command::CommittedImportTarget;
pub(in crate::host) use command::CommittedRosterImportTarget;
use wholepact_core::manual_enrollment::BornManualEnrollmentTerms;
use wholepact_engine::manual_enrollment::ManualEnrollmentTarget;
use wholepact_signer_origin::{ManualEnrollmentLease, manual::HostManualEnrollmentRequest};

pub(super) struct PreparedManualEnrollment<'host> {
    source: ManualEnrollmentOwners<'host>,
    approval: PublicationApproval,
    review_digest: String,
    idempotency_key: String,
}
struct ManualEnrollmentOwners<'host> {
    host: &'host Host,
    engine: ManualEnrollmentTarget<'host>,
    committed: ManualCommittedTarget<'host>,
    history_review: HistoricalApproval,
    financial_origin_digest: String,
    request: HostManualEnrollmentRequest,
}
impl Host {
    pub(super) fn prepare_manual_enrollment<'host>(
        &'host self,
        request: &HostManualEnrollmentRequest,
        idempotency_key: &str,
    ) -> Result<PreparedManualEnrollment<'host>> {
        request.validate().map_err(|_| Error::Invalid)?;
        require_session(self, &request.terms)?;
        // This is separate real private-history consent, not a serialized
        // continuity/status field. No financial or current signer claim follows.
        let review = self.terminal.approve_historical(&format!(
            "Inspect the complete protected ancestor capsule for exact manual-enrollment distinctness.\nCurrent local profile: {}\nAgreement: {}\nObligation: {}\nOnly historical identities/exclusions are compared; this does not spend, prove, sign or submit.",
            self.secrets.profile(), request.terms.scope.agreement_id, request.terms.scope.obligation_id,
        ))?;
        let mut committed = None;
        review.effect(&mut || {
            committed = Some(ManualCommittedTarget::open(&self.directory, &self.secrets)?);
            Ok(())
        })?;
        let committed = committed.ok_or(Error::Authentication)?;
        let engine = self
            .engine
            .manual_enrollment_target(self.access()?, &request.terms)?;
        let financial_origin_digest = self
            .financial
            .as_ref()
            .ok_or(Error::Locked)?
            .manual_journal_origin_digest(&self.directory, &self.secrets)?;
        let source = ManualEnrollmentOwners {
            host: self,
            engine,
            committed,
            history_review: review,
            financial_origin_digest,
            request: request.clone(),
        };
        source.check_current()?;
        let context = wholepact_store::CommandContext::for_request(
            &request.terms.scope.principal_id,
            idempotency_key,
            &serde_json::to_value(request)?,
        )?;
        let review_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-host-manual-enrollment-audit-review:v1",
            &(
                &context,
                source.engine.agreement_record_digest(),
                source.engine.agreement_revision(),
                source.engine.owner_client_id(),
            ),
        )
        .map_err(|_| Error::Authentication)?;
        let detail = format!(
            "Retain one exact manual-enrollment AUDIT record in this already-open recovered host.\nProfile: {}\nRoot: {}\nPrincipal: {}\nAgreement: {}\nObligation: {}\nAccount/FVK commitment: {}/{}\nExact reviewed terms: {}\nStore and journal bindings, complete inherited identity coverage, original signer/witness admission and this native decision are checked independently. This does not create an ordinary authority account, restore a grant, reserve funds, clear historical exposure or enable a financial action.\nExact local review: {}",
            source.committed.profile_id(),
            source.committed.canonical_root(),
            request.terms.scope.principal_id,
            request.terms.scope.agreement_id,
            request.terms.scope.obligation_id,
            request.terms.identity.account_id,
            request.terms.identity.full_viewing_key_digest,
            request.digest().map_err(|_| Error::Invalid)?,
            review_digest,
        );
        let approval = self.terminal.approve_publication(&review_digest, &detail)?;
        source.check_current()?;
        Ok(PreparedManualEnrollment {
            source,
            approval,
            review_digest,
            idempotency_key: idempotency_key.into(),
        })
    }
}
impl ManualEnrollmentOwners<'_> {
    fn check_current(&self) -> Result<()> {
        let terms = &self.request.terms;
        self.history_review.check()?;
        require_session(self.host, terms)?;
        self.committed.check_current()?;
        self.engine.check_current(self.host.access()?)?;
        let financial = self.host.financial.as_ref().ok_or(Error::Locked)?;
        // Attachment V2 composition must use manual_original_primary_origin_digest
        // here and when the continuation owner is captured. Keep the original
        // anchored v1 origin; never substitute the current extension digest.
        let financial_origin = financial
            .manual_original_primary_origin_digest(&self.host.directory, &self.host.secrets)?;
        if financial_origin != self.financial_origin_digest {
            return Err(Error::Authentication);
        }
        require_target_equal(
            terms,
            self.committed.generation_id(),
            self.committed.inventory_digest(),
            self.committed.plan_digest(),
            self.committed.profile_id(),
            self.committed.canonical_root(),
            self.committed.destination_identity_digest(),
            self.engine.store_destination_identity(),
            &financial_origin,
            &self.committed.coverage().digest()?,
        )?;
        // The signer uses its canonical key-derived account identity. The
        // original first-account protocol admits no caller-added aliases.
        self.committed.coverage().require_distinct(
            &terms.identity,
            &BTreeSet::from([terms.identity.account_id.clone()]),
        )
    }
    fn require_lease(&self, lease: &ManualEnrollmentLease<'_>) -> Result<()> {
        if lease.binding() != &self.request {
            return Err(Error::Authentication);
        }
        lease.check_current().map_err(|_| Error::Permission)?;
        self.check_current()
    }
}
impl PreparedManualEnrollment<'_> {
    /// Only appends audit history. Store rechecks exact agreement row and actual
    /// generation inside its bounded IMMEDIATE transaction and consumes the
    /// genuine installed-origin lease. No financial permission is returned.
    pub(super) fn append_audit(
        self,
        lease: ManualEnrollmentLease<'_>,
    ) -> Result<wholepact_store::manual_enrollment::ManualAuditAppendReceipt> {
        self.approval.check()?;
        self.source.require_lease(&lease)?;
        let Self {
            source,
            approval,
            review_digest,
            idempotency_key,
        } = self;
        approval.commit(
            &review_digest,
            || {
                source.require_lease(&lease)?;
                Ok(lease)
            },
            |lease| {
                let result = source.host.engine.append_manual_enrollment_audit(
                    source.host.access()?,
                    &source.engine,
                    &idempotency_key,
                    lease,
                )?;
                // The receipt is audit only. A failure here may follow a durable
                // local append; preserve its exact original idempotency key.
                source.check_current()?;
                Ok(result)
            },
        )
    }
}
fn require_session(host: &Host, terms: &BornManualEnrollmentTerms) -> Result<()> {
    host.directory.check()?;
    let access = host.access()?;
    if access.principal_id != terms.scope.principal_id
        || !host.config.as_ref().is_some_and(|config| {
            config.clients.iter().any(|client| {
                client.client_id == access.principal_id
                    && client.permissions.contains(&Permission::Read)
                    && client.permissions.contains(&Permission::Coordinate)
            })
        })
    {
        return Err(Error::Permission);
    }
    // A short check only; never retain the counted revocation fence while
    // waiting for the signer, witness, native review or a stalled peer.
    host.authority
        .check_financial_principal(&access.principal_id)
}
#[allow(clippy::too_many_arguments)]
fn require_target_equal(
    terms: &BornManualEnrollmentTerms,
    generation: &str,
    inventory: &str,
    plan: &str,
    profile: &str,
    root: &str,
    directory_identity: &str,
    store_identity: &str,
    financial_origin: &str,
    inherited: &str,
) -> Result<()> {
    terms.validate().map_err(|_| Error::Invalid)?;
    require_host_binding_equal(
        &terms.host,
        generation,
        inventory,
        plan,
        profile,
        root,
        directory_identity,
        store_identity,
        financial_origin,
        inherited,
    )
}
#[allow(clippy::too_many_arguments)]
fn require_host_binding_equal(
    target: &wholepact_core::manual_enrollment::ManualHostGenerationBinding,
    generation: &str,
    inventory: &str,
    plan: &str,
    profile: &str,
    root: &str,
    directory_identity: &str,
    store_identity: &str,
    financial_origin: &str,
    inherited: &str,
) -> Result<()> {
    if target.generation_id != generation
        || target.inventory_digest != inventory
        || target.generation_plan_digest != plan
        || target.profile_id != profile
        || target.canonical_root != root
        || target.destination_identity_digest != directory_identity
        || target.store_destination_identity != store_identity
        || target.financial_journal_origin_digest != financial_origin
        || target.inherited_identity_digest != inherited
        || target.scope_predecessor_digest.is_some()
    {
        return Err(Error::RecoveryFinancialUnsupported);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_comparison_rejects_every_cross_owner_substitution() {
        // Pure equality fixture only. It creates no Host, encrypted owner,
        // approval, signer lease or positive PreparedManualEnrollment.
        let target = wholepact_core::manual_enrollment::ManualHostGenerationBinding {
            generation_id: "generation".into(),
            inventory_digest: "inventory".into(),
            generation_plan_digest: "plan".into(),
            financial_journal_origin_digest: "financial".into(),
            store_destination_identity: "store".into(),
            profile_id: "profile".into(),
            canonical_root: "/root".into(),
            destination_identity_digest: "directory".into(),
            inherited_identity_digest: "inherited".into(),
            scope_predecessor_digest: None,
        };
        let actual = [
            "generation",
            "inventory",
            "plan",
            "profile",
            "/root",
            "directory",
            "store",
            "financial",
            "inherited",
        ];
        let check = |values: [&str; 9]| {
            require_host_binding_equal(
                &target, values[0], values[1], values[2], values[3], values[4], values[5],
                values[6], values[7], values[8],
            )
        };
        check(actual).unwrap();
        for index in 0..actual.len() {
            let mut substituted = actual;
            substituted[index] = "different-owner";
            assert!(check(substituted).is_err());
        }
        let mut descendant = target.clone();
        descendant.scope_predecessor_digest = Some("unqualified-successor".into());
        assert!(
            require_host_binding_equal(
                &descendant,
                actual[0],
                actual[1],
                actual[2],
                actual[3],
                actual[4],
                actual[5],
                actual[6],
                actual[7],
                actual[8]
            )
            .is_err()
        );
    }
}
