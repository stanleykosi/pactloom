//! Explicit request-only initial intent, separate private native signer export,
//! then an audit-only append under the genuine bounded lower admission. Only the
//! separate explicit publish-inventory commands add bounded viewing disclosure. This
//! module never manufactures private signer fields or bypasses financial gates.
mod permanent_stop;
mod construction_inspection_v2;
mod construction_inspection_v3;
mod continuation;
mod roster_publication_v2;
mod roster_v2;
use super::*;
pub(in crate::host) use continuation::CommittedImportTarget;
pub(in crate::host) use roster_publication_v2::CommittedRosterImportTarget;
use wholepact_authority::manual_enrollment_signature::ManualEnrollmentExtensionOwnerSignature;
use wholepact_core::manual_enrollment::{BornManualScope, ManualHostGenerationBinding};
use wholepact_engine::manual_enrollment::ManualEnrollmentIntentTarget;
use wholepact_signer_origin::{
    InstalledSignerProvider, NativeManualClient, PairScope, manual::HostManualEnrollmentIntent,
};

/// User-selected limits only. Actual agreement, obligation, principal and all
/// generation/Store/profile/financial origin fields come from held owners.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualScopeSelection {
    participant_id: String,
    privacy_domain: String,
    recipient_scope_digests: Vec<String>,
    aggregate_budget_zatoshis: u64,
    per_operation_limit_zatoshis: u64,
    maximum_fee_share_zatoshis: u64,
    maximum_transaction_fee_zatoshis: u64,
    maximum_permit_lifetime_ms: u64,
    expires_at_ms: u64,
}
struct InitialOwners<'host> {
    host: &'host Host,
    engine: ManualEnrollmentIntentTarget<'host>,
    committed: ManualCommittedTarget<'host>,
    history_review: HistoricalApproval,
    intent: HostManualEnrollmentIntent,
}
impl InitialOwners<'_> {
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
            .manual_journal_origin_digest(&self.host.directory, &self.host.secrets)?;
        require_host_binding_equal(
            &self.intent.host,
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
            || self.intent.scope.agreement_id != agreement.agreement_id
            || self.intent.scope.obligation_id != agreement.obligation_id
            || self.intent.scope.principal_id != self.engine.principal_id()
        {
            return Err(Error::Authentication);
        }
        self.intent.validate().map_err(|_| Error::Invalid)
    }
}
impl Host {
    fn require_manual_session(&self) -> Result<()> {
        self.directory.check()?;
        let principal = &self.access()?.principal_id;
        if !self.config.as_ref().is_some_and(|config| {
            config.clients.iter().any(|client| {
                &client.client_id == principal
                    && has_manual_session_permissions(&client.permissions)
            })
        }) {
            return Err(Error::Permission);
        }
        self.authority.check_financial_principal(principal)
    }
    fn read_manual_private<T: DeserializeOwned>(&self, prompt: &str, reason: &str) -> Result<T> {
        let path = self.path(prompt)?;
        let review = self.terminal.approve_historical(&format!(
            "Read this exact private local file into the current non-signing host for {reason}.\nFile: {}\nNo data is sent by this read. The file grants no authority.", path.display()
        ))?;
        let mut result = None;
        review.effect(&mut || {
            let bytes = Zeroizing::new(files::read_private(&path, 131_072)?);
            result = Some(wholepact_core::parse_typed_json(&bytes).map_err(|_| Error::Invalid)?);
            Ok(())
        })?;
        result.ok_or(Error::Authentication)
    }
    fn prepare_manual_intent<'host>(
        &'host self,
        agreement_id: &str,
        operation_id: String,
        selected: ManualScopeSelection,
    ) -> Result<InitialOwners<'host>> {
        self.require_manual_session()?;
        id(&operation_id)?;
        let engine = self
            .engine
            .manual_enrollment_intent_target(self.access()?, agreement_id)?;
        let history_review = self.terminal.approve_historical(&format!(
            "Inspect complete protected ancestor identity coverage before requesting a new manual enrollment.\nProfile: {}\nAgreement: {}\nObligation: {}\nUnknown legacy coverage denies; this creates no enrollment or financial permission.",
            self.secrets.profile(), engine.agreement().agreement_id, engine.agreement().obligation_id
        ))?;
        let mut committed = None;
        history_review.effect(&mut || {
            committed = Some(ManualCommittedTarget::open(&self.directory, &self.secrets)?);
            Ok(())
        })?;
        let committed = committed.ok_or(Error::Authentication)?;
        committed.coverage().require_complete()?;
        let financial_origin = self
            .financial
            .as_ref()
            .ok_or(Error::Locked)?
            .manual_journal_origin_digest(&self.directory, &self.secrets)?;
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
        let owners = InitialOwners {
            host: self,
            engine,
            committed,
            history_review,
            intent,
        };
        owners.check_current()?;
        Ok(owners)
    }
    pub(in crate::host) fn manual_enrollment_intent_command(&self) -> Result<()> {
        self.require_manual_session()?;
        let agreement_id = self.terminal.ask("Exact current agreement ID: ")?;
        let operation_id = self
            .terminal
            .ask("Original manual enrollment operation ID (preserve for retries): ")?;
        let account_id = self.terminal.ask("Exact canonical account ID shown by the separately installed signer's born-account workspace: ")?;
        require_account_claim(&account_id)?;
        let selection = self.read_manual_private(
            "Private exact one-obligation scope/limit selection JSON file: ",
            "native review of the requested manual scope and limits",
        )?;
        let owners =
            self.prepare_manual_intent(&agreement_id, operation_id.to_string(), selection)?;
        let intent_digest = owners.intent.digest().map_err(|_| Error::Invalid)?;
        let review_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-host-manual-initial-disclosure:v1",
            &(
                &owners.intent,
                account_id.as_str(),
                "fixed-installed-provider-native-launch",
            ),
        )
        .map_err(|_| Error::Invalid)?;
        let approval = self.terminal.approve_publication(&review_digest, &format!(
            "Send these exact host claims to the separately installed signer after its independent native pairing review.\nSelected account claim: {}\nSigner: exact installed native provider, directly launched after this review\nActual agreement owner: {}\nPairing commitment is ENROLLMENT INTENT, not a transaction manifest: {}\n{}\nThis discloses profile/root/principal and exact scope metadata to that signer. It requests no history, viewing key, authorization or financial action. Signer-owned fields are derived there; no terms or permission are returned by this first request.",
            account_id.as_str(), owners.engine.owner_client_id(), intent_digest,
            serde_json::to_string_pretty(&owners.intent)?,
        ))?;
        let pair_approval = self.terminal.approve_publication(&review_digest, &format!(
            "Approve the first finite pairing metadata send to the exact installed signer child.\nAccount claim: {}\nAgreement: {}\nParticipant: {}\nOriginal enrollment intent commitment: {}\nAll private Host fields are separately covered by the preceding exact intent review. No approval is renewable by launch or pairing delay.",
            account_id.as_str(), owners.intent.scope.agreement_id,
            owners.intent.scope.participant_id, intent_digest,
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
                    "wholepact-native-manual-enrollment",
                    PairScope {
                        account_id: account_id.to_string(),
                        agreement_id: owners.intent.scope.agreement_id.clone(),
                        participant_id: owners.intent.scope.participant_id.clone(),
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
                    .submit_enrollment_intent_before(&owners.intent, deadline)
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
        self.terminal.message("Initial request channel closed. Use manual-enrollment-publish with the exact original private export after witness-owner extension review. It collects all Host input/review before launching a fresh signer process for exact pre-Acquire reentry. No financial permission is enabled.\n")
    }
    pub(in crate::host) fn manual_enrollment_publish_command(&self) -> Result<()> {
        self.require_manual_session()?;
        let idempotency_key = self
            .terminal
            .ask("Original Host audit idempotency key (preserve for retries): ")?;
        id(&idempotency_key)?;
        let envelope: ManualEnrollmentExtensionOwnerSignature = self.read_manual_private(
            "Exact ORIGINAL private native signer-exported owner-signature JSON file: ",
            "checking the original signer-derived exact terms against actual current Host owners",
        )?;
        // A file is still untrusted correlation data. Its embedded certificate
        // is NOT installed as an owner pin. The later authenticated live source
        // must match this complete original extension and original stable record.
        envelope.extension.validate().map_err(|_| Error::Invalid)?;
        let request = HostManualEnrollmentRequest {
            terms: envelope.extension.terms.clone(),
        };
        require_account_claim(&request.terms.identity.account_id)?;
        // This reconstructs only the original request-only commitment. The
        // stable first transport binding stays unchanged in request.terms. A new
        // actual pairing is separately approved for this present publication.
        let intent = HostManualEnrollmentIntent {
            version: 1,
            operation_id: request.terms.operation_id.clone(),
            host: request.terms.host.clone(),
            scope: request.terms.scope.clone(),
        };
        intent.validate().map_err(|_| Error::Invalid)?;
        let intent_digest = intent.digest().map_err(|_| Error::Invalid)?;
        let disclosure_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-host-manual-original-publication-disclosure:v1",
            &(&request, &envelope.extension.enrollment_ref, &intent_digest),
        )
        .map_err(|_| Error::Invalid)?;
        let request_approval = self.terminal.approve_publication(&disclosure_digest, &format!(
            "Request publication of this SAME original manual enrollment from the independently installed signer after fresh native pre-Acquire pairing.\nOriginal operation: {}\nOriginal stable enrollment: {}\nSelected account claim: {}\nSigner: exact installed native provider, directly launched after ALL terminal input\nOriginal enrollment intent commitment: {}\nExact original request: {}\nThe exact private terms and original account/birth/policy/host linkage will be sent to that signer. No first record, writer or admission is reset. All remaining Host input and final native review occur now; after pairing, remain in the signer workspace until its exact native writer/publication/disclosure steps finish. The Host will append only audit history automatically if every original deadline and current owner still permits it.",
            request.terms.operation_id, envelope.extension.enrollment_ref,
            request.terms.identity.account_id, intent_digest,
            request.digest().map_err(|_| Error::Invalid)?,
        ))?;
        let pair_approval = self.terminal.approve_publication(&disclosure_digest, &format!(
            "Approve the finite current pairing metadata send for the SAME original enrollment.\nAccount claim: {}\nAgreement: {}\nParticipant: {}\nOriginal intent commitment: {}\nThis is a fresh process review only. First transport, terms, writer/admission history and original deadlines are unchanged.",
            request.terms.identity.account_id, request.terms.scope.agreement_id,
            request.terms.scope.participant_id, intent_digest,
        ))?;
        let prepared = self.prepare_manual_enrollment(&request, &idempotency_key)?;
        let deadline = prepared
            .source
            .history_review
            .deadline()
            .min(prepared.approval.deadline())
            .min(request_approval.deadline())
            .min(pair_approval.deadline());
        prepared.source.check_current()?;
        prepared.approval.check()?;
        request_approval.check()?;
        pair_approval.check()?;
        // No terminal prompt after this point. Endpoint reporting is not a
        // private scope disclosure; all subsequent sends are separately guarded.
        let provider = InstalledSignerProvider::load().map_err(|_| Error::Permission)?;
        provider.launch_native().map_err(|_| Error::Permission)?;
        let endpoint = wait_manual_endpoint_before(&provider, deadline)?;
        prepared.source.check_current()?;
        prepared.approval.check()?;
        request_approval.check()?;
        let pending_pair = pair_approval.commit(
            &disclosure_digest,
            || prepared.source.check_current(),
            |_| {
                NativeManualClient::begin_pair_before(
                    provider,
                    &endpoint,
                    "wholepact-native-manual-publication",
                    PairScope {
                        account_id: request.terms.identity.account_id.clone(),
                        agreement_id: request.terms.scope.agreement_id.clone(),
                        participant_id: request.terms.scope.participant_id.clone(),
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
        let client = pending_pair.finish().map_err(|_| Error::Permission)?;
        prepared.source.check_current()?;
        prepared.approval.check()?;
        // Finite connect/write only under exact native disclosure commit. The
        // wait for queued signer review and Held occurs after the lock is gone.
        let pending = request_approval.commit(
            &disclosure_digest,
            || prepared.source.check_current(),
            |_| {
                client
                    .begin_enrollment_before(&request, deadline)
                    .map_err(|_| Error::Permission)
            },
        )?;
        let lease = pending.finish().map_err(|_| Error::Permission)?;
        let evidence = lease.evidence();
        if evidence.enrollment_ref != envelope.extension.enrollment_ref
            || evidence.witness_extension_digest
                != envelope.extension.digest().map_err(|_| Error::Invalid)?
            || evidence.witness_extension_sequence != envelope.extension.sequence
            || evidence.witness_extension_predecessor_digest
                != envelope.extension.predecessor_digest
        {
            return Err(Error::Authentication);
        }
        let receipt = prepared.append_audit(lease)?;
        self.terminal.message(&format!(
            "Exact manual enrollment audit retained. Operation: {}. Enrollment reference: {}. Audit digest: {}. Replayed exact original: {}. This audit grants no financial permission.\n",
            receipt.operation_id(), receipt.enrollment_ref(), receipt.audit_digest(), receipt.replayed(),
        ))
    }
}
fn wait_manual_endpoint_before(
    provider: &InstalledSignerProvider,
    deadline: std::time::Instant,
) -> Result<PathBuf> {
    let remaining = deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(Error::Permission)?;
    let endpoint = provider
        .wait_native_endpoint(remaining.min(Duration::from_secs(120)))
        .map_err(|_| Error::Permission)?;
    if std::time::Instant::now() >= deadline {
        return Err(Error::Permission);
    }
    Ok(endpoint)
}
fn require_account_claim(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initial_selection_cannot_supply_host_or_signer_identity() {
        // Strict request shape only; no actual owners, file reads, pairing,
        // native approvals or positive enrollment capability are constructed.
        let value = serde_json::json!({
            "participant_id":"participant", "privacy_domain":"domain",
            "recipient_scope_digests":["aa".repeat(32)], "aggregate_budget_zatoshis":1,
            "per_operation_limit_zatoshis":1,"maximum_fee_share_zatoshis":0,
            "maximum_transaction_fee_zatoshis":0,"maximum_permit_lifetime_ms":1,
            "expires_at_ms":2
        });
        assert!(serde_json::from_value::<ManualScopeSelection>(value.clone()).is_ok());
        for field in ["host", "terms", "principal_id", "obligation_id", "approved"] {
            let mut altered = value.clone();
            altered[field] = serde_json::json!(true);
            assert!(serde_json::from_value::<ManualScopeSelection>(altered).is_err());
        }
        for account in ["", "label", &"A".repeat(64), &"a".repeat(63)] {
            assert!(require_account_claim(account).is_err());
        }
        assert!(require_account_claim(&"a".repeat(64)).is_ok());
    }
}

/// Pure permission membership only. The actual caller also checks its current
/// native principal, configured client identity, live session and exact target.
fn has_manual_session_permissions(permissions: &BTreeSet<Permission>) -> bool {
    [
        Permission::Read,
        Permission::Coordinate,
        Permission::Disclose,
    ]
    .iter()
    .all(|permission| permissions.contains(permission))
}
#[cfg(test)]
mod manual_session_policy_tests {
    use super::*;
    #[test]
    fn every_manual_session_permission_is_required() {
        assert!(has_manual_session_permissions(&BTreeSet::from([
            Permission::Read,
            Permission::Coordinate,
            Permission::Disclose
        ])));
        for incomplete in [
            vec![],
            vec![Permission::Read, Permission::Coordinate],
            vec![Permission::Read, Permission::Disclose],
            vec![Permission::Coordinate, Permission::Disclose],
        ] {
            assert!(!has_manual_session_permissions(
                &incomplete.into_iter().collect()
            ));
        }
        // Membership is not session/native/target authority; no owner is created.
    }
}
