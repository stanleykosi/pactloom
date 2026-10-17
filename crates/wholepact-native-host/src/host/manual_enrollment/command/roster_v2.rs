//! Separately reviewed additional-account request. Source staging only; final
//! publication and command dispatch are separate required composition steps.
#[cfg(test)]
pub(super) mod joined_intent_v3;
use super::*;
use wholepact_engine::manual_enrollment::ManualRosterIntentTarget;
use wholepact_signer_origin::manual_roster_v2::HostManualRosterEnrollmentIntentV2;

struct RosterInitialOwners<'host> {
    host: &'host Host,
    engine: ManualRosterIntentTarget<'host>,
    committed: ManualCommittedTarget<'host>,
    history_review: HistoricalApproval,
    intent: HostManualRosterEnrollmentIntentV2,
}
impl RosterInitialOwners<'_> {
    fn check_current(&self) -> Result<()> {
        self.history_review.check()?;
        self.host.require_manual_session()?;
        self.engine.check_current(self.host.access()?)?;
        self.committed.check_current()?;
        self.committed.coverage().require_complete()?;
        let origin = self
            .host
            .financial
            .as_ref()
            .ok_or(Error::Locked)?
            .manual_original_primary_origin_digest(&self.host.directory, &self.host.secrets)?;
        require_host_binding_equal(
            &self.intent.account_intent.host,
            self.committed.generation_id(),
            self.committed.inventory_digest(),
            self.committed.plan_digest(),
            self.committed.profile_id(),
            self.committed.canonical_root(),
            self.committed.destination_identity_digest(),
            self.engine.store_destination_identity(),
            &origin,
            &self.committed.coverage().digest()?,
        )?;
        let agreement = self.engine.agreement();
        if self.engine.generation_id() != self.committed.generation_id()
            || self.engine.inventory_digest() != self.committed.inventory_digest()
            || self.intent.account_intent.scope.agreement_id != agreement.agreement_id
            || self.intent.account_intent.scope.obligation_id != agreement.obligation_id
            || self.intent.account_intent.scope.principal_id != self.engine.principal_id()
        {
            return Err(Error::Authentication);
        }
        if &self.intent.roster != self.engine.binding() {
            return Err(Error::Authentication);
        }
        self.intent.validate().map_err(|_| Error::Invalid)
    }
}
impl Host {
    fn prepare_manual_roster_intent<'host>(
        &'host self,
        agreement_id: &str,
        operation_id: String,
        selected: ManualScopeSelection,
    ) -> Result<RosterInitialOwners<'host>> {
        self.require_manual_session()?;
        id(&operation_id)?;
        let public_target = self
            .engine
            .manual_enrollment_intent_target(self.access()?, agreement_id)?;
        let history_review = self.terminal.approve_historical(&format!(
            "Inspect complete protected ancestor identity coverage before requesting a new manual enrollment.\nProfile: {}\nAgreement: {}\nObligation: {}\nUnknown legacy coverage denies; this creates no enrollment or financial permission.",
            self.secrets.profile(), public_target.agreement().agreement_id, public_target.agreement().obligation_id
        ))?;
        let mut committed = None;
        let mut engine = None;
        history_review.effect(&mut || {
            public_target.check_current(self.access()?)?;
            committed = Some(ManualCommittedTarget::open(&self.directory, &self.secrets)?);
            engine = Some(
                self.engine
                    .manual_roster_intent_target(self.access()?, agreement_id)?,
            );
            Ok(())
        })?;
        let committed = committed.ok_or(Error::Authentication)?;
        let engine = engine.ok_or(Error::Authentication)?;
        committed.coverage().require_complete()?;
        let financial_origin = self
            .financial
            .as_ref()
            .ok_or(Error::Locked)?
            .manual_original_primary_origin_digest(&self.directory, &self.secrets)?;
        let intent = HostManualEnrollmentIntent {
            version: 1,
            operation_id,
            host: ManualHostGenerationBinding {
                generation_id: committed.generation_id().into(),
                inventory_digest: committed.inventory_digest().into(),
                generation_plan_digest: committed.plan_digest().into(),
                financial_journal_origin_digest: financial_origin,
                store_destination_identity: engine.store_destination_identity().into(),
                profile_id: committed.profile_id().into(),
                canonical_root: committed.canonical_root().into(),
                destination_identity_digest: committed.destination_identity_digest().into(),
                inherited_identity_digest: committed.coverage().digest()?,
                scope_predecessor_digest: None,
            },
            scope: BornManualScope {
                agreement_id: engine.agreement().agreement_id.clone(),
                obligation_id: engine.agreement().obligation_id.clone(),
                participant_id: selected.participant_id,
                principal_id: engine.principal_id().into(),
                privacy_domain: selected.privacy_domain,
                recipient_scope_digests: selected.recipient_scope_digests,
                aggregate_budget_zatoshis: selected.aggregate_budget_zatoshis,
                per_operation_limit_zatoshis: selected.per_operation_limit_zatoshis,
                maximum_fee_share_zatoshis: selected.maximum_fee_share_zatoshis,
                maximum_transaction_fee_zatoshis: selected.maximum_transaction_fee_zatoshis,
                maximum_permit_lifetime_ms: selected.maximum_permit_lifetime_ms,
                expires_at_ms: selected.expires_at_ms,
            },
        };
        let intent = HostManualRosterEnrollmentIntentV2 {
            version: 2,
            account_intent: intent,
            roster: engine.binding().clone(),
        };
        let owners = RosterInitialOwners {
            host: self,
            engine,
            committed,
            history_review,
            intent,
        };
        owners.check_current()?;
        Ok(owners)
    }
    pub(in crate::host) fn manual_roster_enrollment_intent_v2_command(&self) -> Result<()> {
        self.require_manual_session()?;
        let agreement_id = self.terminal.ask("Exact current agreement ID: ")?;
        let operation_id = self
            .terminal
            .ask("Original additional-account roster operation ID (preserve for retries): ")?;
        let account_id = self.terminal.ask("Exact canonical account ID shown by the separately installed signer's born-account workspace: ")?;
        require_account_claim(&account_id)?;
        let selection = self.read_manual_private(
            "Private exact one-obligation scope/limit selection JSON file: ",
            "native review of the requested manual scope and limits",
        )?;
        let owners =
            self.prepare_manual_roster_intent(&agreement_id, operation_id.to_string(), selection)?;
        owners.check_current()?;
        let members_json = serde_json::to_string_pretty(owners.engine.members(self.access()?)?)?;
        owners.check_current()?;
        let intent_digest = owners.intent.digest().map_err(|_| Error::Invalid)?;
        let review_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-host-manual-roster-disclosure:v2",
            &(
                &owners.intent,
                &members_json,
                account_id.as_str(),
                "fixed-installed-provider-native-launch",
            ),
        )
        .map_err(|_| Error::Invalid)?;
        let approval = self.terminal.approve_publication_reviewed(&owners.history_review, &review_digest, &format!(
            "Retained roster members: {}\nAdd one distinct newly-born account to this exact existing Host roster. Send these exact host claims to the separately installed signer after its independent native pairing review.\nSelected account claim: {}\nSigner: exact installed native provider, directly launched after this review\nActual agreement owner: {}\nPairing commitment is EXACT ROSTER ENROLLMENT INTENT: {}\n{}\nThis discloses profile/root/principal and exact scope metadata to that signer. It requests no history, viewing key, authorization or financial action. Signer-owned fields are derived there; no terms or permission are returned by this first request.",
            members_json, account_id.as_str(), owners.engine.owner_client_id(), intent_digest,
            serde_json::to_string_pretty(&owners.intent)?,
        ))?;
        let pair_approval = self.terminal.approve_publication_reviewed(&owners.history_review, &review_digest, &format!(
            "Approve the first finite pairing metadata send to the exact installed signer child.\nAccount claim: {}\nAgreement: {}\nParticipant: {}\nOriginal enrollment intent commitment: {}\nAll private Host fields are separately covered by the preceding exact intent review. No approval is renewable by launch or pairing delay.",
            account_id.as_str(), owners.intent.account_intent.scope.agreement_id,
            owners.intent.account_intent.scope.participant_id, intent_digest,
        ))?;
        let deadline = owners
            .history_review
            .deadline()
            .min(approval.deadline())
            .min(pair_approval.deadline());
        owners.check_current()?;
        approval.check()?;
        pair_approval.check()?;
        let provider = InstalledSignerProvider::load().map_err(|_| Error::Permission)?;
        // Launch/endpoint reporting carries no account or Host scope. Recheck
        // actual native owners AFTER waiting, before the first metadata send.
        provider.launch_native().map_err(|_| Error::Permission)?;
        let endpoint = wait_manual_endpoint_before(&provider, deadline)?;
        owners.check_current()?;
        approval.check()?;
        let pending = pair_approval.commit(
            &review_digest,
            || owners.check_current(),
            |_| {
                NativeManualClient::begin_pair_before(
                    provider,
                    &endpoint,
                    "wholepact-native-manual-roster-enrollment-v2",
                    PairScope {
                        account_id: account_id.to_string(),
                        agreement_id: owners.intent.account_intent.scope.agreement_id.clone(),
                        participant_id: owners.intent.account_intent.scope.participant_id.clone(),
                        manifest_digest: intent_digest,
                        history_read: false,
                        authorization_export: false,
                        preconstruction_export: false,
                    },
                    deadline,
                )
                .map_err(|_| Error::Permission)
            },
        )?;
        // Native pairing review waits with no terminal/publication lock held.
        let client = pending.finish().map_err(|_| Error::Permission)?;
        // The potentially interactive pairing wait occurs with no global/native
        // authority or witness lock held. The actual write is bounded separately.
        approval.commit(
            &review_digest,
            || owners.check_current(),
            |_| {
                client
                    .submit_roster_enrollment_intent_v2_before(&owners.intent, deadline)
                    .map_err(|_| Error::Permission)
            },
        )?;
        // Drop the complete historical capsule, real Store target and spent
        // initial review before waiting for the user. None can be stretched
        // into a capability across the signer export/witness focus handoff.
        drop(owners);
        // The client is retained solely because its provider owns the launched
        // child's private parent channel. No request/current/lease method is
        // called again. The signer's original native deadline/focus revocation
        // continues independently; keeping this channel does not renew it.
        self.terminal.message("Request-only intent queued. STAY IN THE SIGNER WINDOW to finish the exact original record retention, owner signature and private export. Do not acquire a writer. ONLY AFTER that phase, return to this terminal to close its launcher channel; returning invalidates the native focus authority. Then complete the separate witness-owner extension review. This Host receives no export-success or authority claim.\n")?;
        let _cleanup_only = self.terminal.ask("After leaving the initial signer phase, press Enter to close its request channel (cleanup only): ")?;
        drop(client);
        self.terminal.message("Initial request channel closed. Use manual-roster-enrollment-publish-v2 with the exact original private export after witness-owner extension review. It collects all Host input/review before launching a fresh signer process for exact pre-Acquire reentry. No financial permission is enabled.\n")
    }
}
