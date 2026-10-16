//! Dedicated restriction publication. Historical files and informational
//! retirement observations are not accepted as source, consent or exclusion proof.
use super::*;
use wholepact_engine::manual_enrollment::ManualPermanentStopTargetV1;
use wholepact_signer_origin::permanent_stop_v1::require_activation_v1;

struct StopOwners<'host> {
    host: &'host Host,
    target: ManualPermanentStopTargetV1<'host>,
    committed: ManualCommittedTarget<'host>,
    history_review: HistoricalApproval,
}
impl StopOwners<'_> {
    fn check_current(&self) -> Result<()> {
        self.history_review.check()?;
        self.host.require_manual_session()?;
        let terms = self.target.terms();
        require_session(self.host, terms)?;
        self.target.check_current(self.host.access()?)?;
        self.committed.check_current()?;
        self.committed.coverage().require_complete()?;
        let financial_origin = self
            .host
            .financial
            .as_ref()
            .ok_or(Error::Locked)?
            .manual_original_primary_origin_digest(&self.host.directory, &self.host.secrets)?;
        require_target_equal(
            terms,
            self.committed.generation_id(),
            self.committed.inventory_digest(),
            self.committed.plan_digest(),
            self.committed.profile_id(),
            self.committed.canonical_root(),
            self.committed.destination_identity_digest(),
            self.target.store_destination_identity(),
            &financial_origin,
            &self.committed.coverage().digest()?,
        )?;
        self.committed
            .coverage()
            .require_distinct(&terms.identity, &self.target.original().aliases)
    }
}
impl Host {
    pub(in crate::host) fn manual_permanent_stop_publish_v1_command(&self) -> Result<()> {
        // Shared native/kernel qualification gate is FIRST, before prompts,
        // private-history reads, provider load, launch, pairing or Store mutation.
        require_activation_v1().map_err(|_| Error::Permission)?;
        self.manual_permanent_stop_publish_v1_staged()
    }
    fn manual_permanent_stop_publish_v1_staged(&self) -> Result<()> {
        self.require_manual_session()?;
        let agreement_id = self.terminal.ask("Exact enrolled account agreement ID: ")?;
        let account_id = self
            .terminal
            .ask("Exact canonical enrolled account ID to restrict: ")?;
        require_account_claim(&account_id)?;
        id(&agreement_id)?;
        let history_review = self.terminal.approve_historical(&format!(
            "Read the exact current-generation Host roster enrollment and complete protected inherited identity coverage.\nProfile: {}\nAgreement: {}\nAccount: {}\nThese identifiers only select existing authenticated local records. No file or caller claim supplies ownership, original scope, aliases, signer or witness evidence. This step sends nothing and grants no financial permission.", self.secrets.profile(), agreement_id.as_str(), account_id.as_str()
        ))?;
        let mut selected = None;
        history_review.effect(&mut || {
            selected = Some((
                self.engine.manual_permanent_stop_target_v1(
                    self.access()?,
                    &agreement_id,
                    &account_id,
                )?,
                ManualCommittedTarget::open(&self.directory, &self.secrets)?,
            ));
            Ok(())
        })?;
        let (target, committed) = selected.ok_or(Error::Authentication)?;
        let owners = StopOwners {
            host: self,
            target,
            committed,
            history_review,
        };
        owners.check_current()?;
        let request = owners.target.request();
        let digest = request.digest().map_err(|_| Error::Invalid)?;
        let publication = self.terminal.approve_publication(&digest, &format!(
            "RETAIN THE SIGNER'S EXISTING PERMANENT ROUTINE-USE EXCLUSION\nLocal Host profile/root: {} / {}\nExact current agreement record: {}\nOriginal Host roster audit: {}\nExact request:\n{}\n\nAfter the independently installed signer confirms its genuine locally retained exclusion and original witness receipt, retain the restriction and its original provenance atomically in this Host. Only then send an exact durable acknowledgment back to that same peer. A lost acknowledgment never removes the restriction. Exact retries return first-saved history and receipt digests; do not reset account, aliases, genesis, policy, budgets or exposure. This does not reclaim funds, assert an empty account, settle outstanding authorizations, hide/delete history, enable a financial workflow or revoke an already disclosed viewing key.",
            owners.committed.profile_id(), owners.committed.canonical_root(), owners.target.agreement_record_digest(), request.original_host_audit_digest, serde_json::to_string_pretty(request)?
        ))?;
        let disclosure = self.terminal.approve_publication(&digest, &format!(
            "Disclose the exact request shown above to its original independently installed signer after fresh native pairing. It contains original account/FVK commitment, Host generation/profile/root, principal, agreement/obligation/scope, roster predecessor, provider and original Host audit. No raw FVK, seed, key or signature is sent. This asks only to publish an already retained permanent restriction.\nExact request: {digest}"
        ))?;
        let pairing = self.terminal.approve_publication(&digest, &format!(
            "Send the bounded pairing metadata for this exact permanent-restriction request to its original installed signer.\nAccount: {}\nAgreement: {}\nParticipant: {}\nRequest commitment: {}\nHistory, authorization and preconstruction pairing permissions remain false. A prior informational retirement observation or old pairing grants no authority.",
            request.original.enrollment.terms.identity.account_id, request.original.enrollment.terms.scope.agreement_id, request.original.enrollment.terms.scope.participant_id, digest
        ))?;
        let deadline = owners
            .history_review
            .deadline()
            .min(publication.deadline())
            .min(disclosure.deadline())
            .min(pairing.deadline());
        owners.check_current()?;
        publication.check()?;
        disclosure.check()?;
        pairing.check()?;
        let provider = InstalledSignerProvider::load().map_err(|_| Error::Permission)?;
        if provider.native_enrollment_reference() != request.provider_enrollment_ref {
            return Err(Error::Authentication);
        }
        provider.launch_native().map_err(|_| Error::Permission)?;
        let endpoint = wait_manual_endpoint_before(&provider, deadline)?;
        let pending = pairing.commit(
            &digest,
            || {
                owners.check_current()?;
                publication.check()?;
                disclosure.check()
            },
            |_| {
                NativeManualClient::begin_pair_before(
                    provider,
                    &endpoint,
                    "wholepact-permanent-restriction-publication-v1",
                    request.pair_scope().map_err(|_| Error::Invalid)?,
                    deadline,
                )
                .map_err(|_| Error::Permission)
            },
        )?;
        let client = pending.finish().map_err(|_| Error::Permission)?;
        owners.check_current()?;
        publication.check()?;
        let pending = disclosure.commit(
            &digest,
            || {
                owners.check_current()?;
                publication.check()
            },
            |_| {
                client
                    .begin_permanent_stop_v1_before(request, deadline)
                    .map_err(|_| Error::Permission)
            },
        )?;
        // The native signer decision waits outside the Host's terminal write lock.
        let lease = pending.finish().map_err(|_| Error::Permission)?;
        owners.check_current()?;
        let receipt = publication.commit(
            &digest,
            || {
                owners.check_current()?;
                if lease.evidence().request != *request {
                    return Err(Error::Authentication);
                }
                lease.check_current().map_err(|_| Error::Permission)?;
                Ok(lease)
            },
            |lease| {
                let result = self.engine.append_manual_permanent_stop_v1(
                    self.access()?,
                    &owners.target,
                    lease,
                )?;
                owners.check_current()?;
                Ok(result)
            },
        )?;
        self.terminal.json(&serde_json::json!({
            "status": "permanent_routine_use_restriction_retained_and_acknowledged",
            "publication_digest": receipt.publication().digest()?,
            "restriction_audit_digest": receipt.publication().exclusion.digest()?,
            "original_host_audit_digest": receipt.publication().original_host_audit_digest,
            "exact_retry": receipt.replayed(),
            "funds_reclaimed": false,
            "account_emptiness_established": false,
            "outstanding_authorizations_cleared": false,
            "viewing_disclosure_revoked": false
        }))
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn restriction_publication_activation_stays_closed_before_any_host_effect() {
        assert!(matches!(
            wholepact_signer_origin::permanent_stop_v1::require_activation_v1(),
            Err(wholepact_signer_origin::Error::PermanentStopUnavailable)
        ));
    }
}
