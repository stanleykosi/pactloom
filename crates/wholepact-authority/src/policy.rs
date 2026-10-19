//! Deterministic, side-effect-free authority state transition and accounting.
use crate::exposure_view::ExposureView;
use crate::reservation_view::ReservationView;
use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Event {
    pub mutation: AuthorityMutation,
    pub authenticated_certificate_digest: String,
    pub witness_time_ms: u64,
    pub writer_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_request_link: Option<crate::offline_retry::OriginalCommitLink>,
}

pub(crate) struct Ledger {
    pub(crate) account_use_history: crate::account_use::AccountUseHistory,
    pub(crate) offline_policies: BTreeMap<String, crate::offline::OfflineEnrollmentPolicy>,
    pub(crate) offline_policy_states: BTreeMap<String, (String, OfflineEnrollmentStatus)>,
    pub(crate) offline_intents: BTreeSet<String>,
    pub(crate) offline_intent_digests: BTreeSet<String>,
    pub(crate) automation_account_policy: Option<WitnessAutomationAccountPolicy>,
    pub(crate) automation_account_policies: BTreeMap<String, WitnessAutomationAccountPolicy>,
    pub(crate) automation_grants: BTreeMap<String, WitnessAutomationGrant>,
    pub(crate) automatic_key_uses: BTreeSet<String>,
    pub policy: AccountPolicy,
    pub snapshot: AccountSnapshot,
    pub(crate) operations: BTreeMap<String, (AuthorityMutation, String, MutationResult)>,
    pub(crate) authorizations: BTreeSet<String>,
    consents: BTreeSet<String>,
    pub(crate) obligations: BTreeSet<String>,
    pub(crate) input_ids: BTreeSet<String>,
    pub(crate) nullifiers: BTreeSet<String>,
    pub sessions: BTreeMap<String, WriterSessionReceipt>,
    pub activated_sessions: BTreeSet<String>,
    pub(crate) final_transactions: BTreeMap<String, (String, String)>,
    pub(crate) resolutions: BTreeMap<String, ResolutionReceipt>,
    pub(crate) resolution_source: Option<String>,
}
impl Ledger {
    #[cfg(any(test, feature = "synthetic-qualification"))]
    pub fn historical_session(&self, operation: &str) -> Option<&str> {
        self.operations
            .get(operation)
            .and_then(|(_, _, result)| match result {
                MutationResult::Reserved(p) => Some(p.writer_session_id.as_str()),
                MutationResult::OfflineReserved(p) => Some(p.writer_session_id.as_str()),
                MutationResult::BornOfflineReservedV1(p) => {
                    Some(p.reserved.writer_session_id.as_str())
                }
                MutationResult::DispatchAdmitted(p) => Some(p.writer_session_id.as_str()),
                MutationResult::AutomaticKeyUseAdmitted(p) => Some(p.writer_session_id.as_str()),
                _ => None,
            })
    }
    pub fn admitted_certificates(&self) -> BTreeSet<&str> {
        let mut allowed = BTreeSet::from([
            self.policy.owner_certificate_digest.as_str(),
            self.policy.initial_writer_certificate_digest.as_str(),
        ]);
        for (mutation, _, _) in self.operations.values() {
            if let AuthorityMutation::OwnerControl(OwnerControlRequest {
                control:
                    OwnerControl::ReplaceWriter {
                        writer_certificate_digest,
                    }
                    | OwnerControl::RecoverWriter {
                        writer_certificate_digest,
                        ..
                    },
                ..
            }) = mutation
            {
                allowed.insert(writer_certificate_digest.as_str());
            }
        }
        allowed
    }
    pub fn new(policy: AccountPolicy) -> Result<Self> {
        policy.validate()?;
        let policy_digest = policy.policy_digest()?;
        let account_use_history = match &policy.account_use_genesis {
            Some(g) => crate::account_use::AccountUseHistory::from_policy_genesis(
                g.clone(),
                &policy.account_id,
                &policy.network_profile_id,
                &policy.witness_id,
                &policy.owner_certificate_digest,
            )?,
            None => crate::account_use::AccountUseHistory::unknown_legacy(),
        };
        let snapshot = AccountSnapshot {
            transport_fences: None,
            account_use_checkpoint: account_use_history.checkpoint()?,
            witness_id: policy.witness_id.clone(),
            account_id: policy.account_id.clone(),
            network_profile_id: policy.network_profile_id.clone(),
            policy_digest: policy_digest.clone(),
            head: AuthorityHead {
                sequence: 0,
                digest: policy_digest,
            },
            writer_epoch: policy.initial_writer_epoch,
            writer_certificate_digest: policy.initial_writer_certificate_digest.clone(),
            writer_status: WriterStatus::Active,
            outstanding_reservations: 0,
            outstanding_debit_zatoshis: 0,
            settled_debit_zatoshis: 0,
            aggregate_budget_zatoshis: policy.aggregate_budget_zatoshis,
            reserved_input_value_zatoshis: 0,
            last_witness_time_ms: 0,
            pending_writer_session: None,
            active_writer_session: None,
        };
        Ok(Self {
            account_use_history,
            offline_policies: BTreeMap::new(),
            offline_policy_states: BTreeMap::new(),
            offline_intents: BTreeSet::new(),
            offline_intent_digests: BTreeSet::new(),
            automation_account_policy: None,
            automation_account_policies: BTreeMap::new(),
            automation_grants: BTreeMap::new(),
            automatic_key_uses: BTreeSet::new(),
            policy,
            snapshot,
            operations: BTreeMap::new(),
            authorizations: BTreeSet::new(),
            consents: BTreeSet::new(),
            obligations: BTreeSet::new(),
            input_ids: BTreeSet::new(),
            nullifiers: BTreeSet::new(),
            sessions: BTreeMap::new(),
            activated_sessions: BTreeSet::new(),
            final_transactions: BTreeMap::new(),
            resolutions: BTreeMap::new(),
            resolution_source: None,
        })
    }
    pub fn authenticate_read(&self, peer: &str, account: &str, network: &str) -> Result<()> {
        if account != self.policy.account_id
            || network != self.policy.network_profile_id
            || (peer != self.policy.owner_certificate_digest
                && peer != self.snapshot.writer_certificate_digest)
        {
            return Err(AuthorityError::Permission);
        }
        Ok(())
    }
    /// Authenticate before exposing operation presence, conflict or quarantine.
    /// A former writer may retrieve only its own retained reservation identity;
    /// it gains no current writer privileges or access to other operations.
    pub fn authenticate_mutation(&self, event: &Event) -> Result<()> {
        let peer = &event.authenticated_certificate_digest;
        let (account, network, permitted) = match &event.mutation {
            AuthorityMutation::ClaimConstructionTransportV1(r) => {
                let pending = self.construction_transport_grant(&r.claim.pending_grant_digest)?;
                let a = &pending.grant.authorization.authorization;
                if a.account_id != self.policy.account_id
                    || a.network_profile_id != self.policy.network_profile_id
                    || peer != &a.original_session.writer_certificate_digest
                {
                    return Err(AuthorityError::Permission);
                }
                (
                    &self.policy.account_id,
                    &self.policy.network_profile_id,
                    true,
                )
            }
            AuthorityMutation::UseConstructionTransportV1(r) => {
                let c = self.construction_transport_credential(&r.credential_id)?;
                (
                    &self.policy.account_id,
                    &self.policy.network_profile_id,
                    peer == &c.authorization().original_session.writer_certificate_digest,
                )
            }
            AuthorityMutation::ReserveManualRosterConstructionV3(r) => (
                &r.enrollment().identity.account_id,
                &r.enrollment().identity.network_profile_id,
                peer == &self.snapshot.writer_certificate_digest,
            ),
            AuthorityMutation::ConsumeManualRosterConstructionV3(r) => (
                &r.account_id,
                &r.network_profile_id,
                peer == &self.snapshot.writer_certificate_digest,
            ),
            AuthorityMutation::ReserveManualRosterConstructionV2(r) => (
                &r.enrollment().identity.account_id,
                &r.enrollment().identity.network_profile_id,
                peer == &self.snapshot.writer_certificate_digest,
            ),
            AuthorityMutation::ConsumeManualRosterConstructionV2(r) => (
                &r.account_id,
                &r.network_profile_id,
                peer == &self.snapshot.writer_certificate_digest,
            ),
            AuthorityMutation::AdmitBornManualRosterEnrollmentV2(r) => (
                &r.account_id,
                &r.network_profile_id,
                peer == &self.snapshot.writer_certificate_digest,
            ),
            AuthorityMutation::AdmitBornManualEnrollmentV2(r) => (
                &r.account_id,
                &r.network_profile_id,
                peer == &self.snapshot.writer_certificate_digest,
            ),
            AuthorityMutation::AdmitBornManualEnrollment(r) => (
                &r.account_id,
                &r.network_profile_id,
                peer == &self.snapshot.writer_certificate_digest,
            ),
            AuthorityMutation::ReserveBornOfflineV1(record) => {
                let r = &record.request.reservation;
                (
                    &r.intent.terms.account_id,
                    &r.intent.terms.network_profile_id,
                    self.born_offline_enrollment_v1()?
                        .is_some_and(|e| peer == e.enrollment.born_transport_certificate_v1()),
                )
            }
            AuthorityMutation::ReserveOfflineAuthorization(record) => {
                let r = &record.request;
                let original =
                    self.operations
                        .get(&r.operation_id)
                        .is_some_and(|(old, peer_before, _)| {
                            peer_before == peer
                                && matches!(old, AuthorityMutation::ReserveOfflineAuthorization(_))
                        });
                (
                    &r.intent.terms.account_id,
                    &r.intent.terms.network_profile_id,
                    peer == &self.snapshot.writer_certificate_digest || original,
                )
            }
            AuthorityMutation::AuthorizeAutomaticKeyUse(r) => (
                &r.account_id,
                &r.network_profile_id,
                peer == &self.snapshot.writer_certificate_digest,
            ),
            AuthorityMutation::ReserveAuthorization(r) => {
                let owns_historical_reservation =
                    self.operations
                        .get(&r.operation_id)
                        .is_some_and(|(old, original_peer, _)| {
                            original_peer == peer
                                && matches!(old, AuthorityMutation::ReserveAuthorization(_))
                        });
                (
                    &r.account_id,
                    &r.network_profile_id,
                    peer == &self.snapshot.writer_certificate_digest || owns_historical_reservation,
                )
            }
            AuthorityMutation::AuthorizeBornOfflineDispatchV1(r) => {
                let original = self.operations.get(&r.dispatch.operation_id).is_some_and(
                    |(old, original, _)| {
                        original == peer
                            && matches!(old, AuthorityMutation::AuthorizeBornOfflineDispatchV1(_))
                    },
                );
                (
                    &r.dispatch.account_id,
                    &r.dispatch.network_profile_id,
                    self.born_offline_enrollment_v1()?
                        .is_some_and(|e| peer == e.enrollment.born_transport_certificate_v1())
                        || original,
                )
            }
            AuthorityMutation::AuthorizeDispatch(r) => {
                let owns_historical =
                    self.operations
                        .get(&r.operation_id)
                        .is_some_and(|(old, original, _)| {
                            original == peer
                                && matches!(old, AuthorityMutation::AuthorizeDispatch(_))
                        });
                (
                    &r.account_id,
                    &r.network_profile_id,
                    peer == &self.snapshot.writer_certificate_digest || owns_historical,
                )
            }
            AuthorityMutation::AcquireWriter(r) => (
                &r.account_id,
                &r.network_profile_id,
                peer == &self.snapshot.writer_certificate_digest,
            ),
            AuthorityMutation::ReportProgress(r) => {
                let original = self
                    .operations
                    .get(&r.reservation_operation_id)
                    .is_some_and(|(_, original, result)| {
                        original == peer && ReservationView::from_result(result).is_some()
                    });
                (
                    &r.account_id,
                    &r.network_profile_id,
                    peer == &self.snapshot.writer_certificate_digest || original,
                )
            }
            AuthorityMutation::QualifiedResolution(r) => (
                &r.account_id,
                &r.network_profile_id,
                peer == &self.policy.owner_certificate_digest,
            ),
            AuthorityMutation::ReopenResolutions(r) => (
                &r.account_id,
                &r.network_profile_id,
                peer == &self.policy.owner_certificate_digest,
            ),
            AuthorityMutation::OwnerControl(r) => (
                &r.account_id,
                &r.network_profile_id,
                peer == &self.policy.owner_certificate_digest,
            ),
        };
        if account != &self.policy.account_id
            || network != &self.policy.network_profile_id
            || !permitted
        {
            return Err(AuthorityError::Permission);
        }
        Ok(())
    }
    /// Exact replays are historical permits even after control changes or expiry.
    /// They never add exposure and never represent a new authorization decision.
    pub fn replay(&self, event: &Event) -> Result<Option<MutationResult>> {
        self.authenticate_mutation(event)?;
        if let Some((old, peer, result)) = self.operations.get(event.mutation.operation_id()) {
            if old != &event.mutation || peer != &event.authenticated_certificate_digest {
                return Err(AuthorityError::Conflict);
            }
            return Ok(Some(result.clone()));
        }
        Ok(None)
    }
    pub fn apply(&mut self, event: &Event) -> Result<MutationResult> {
        self.require_delivery_admission_only_v2(&event.mutation)?;
        if event.original_request_link.is_some()
            && !matches!(
                event.mutation,
                AuthorityMutation::ReserveOfflineAuthorization(_)
            )
        {
            return Err(AuthorityError::InvalidBinding);
        }
        if let Some(result) = self.replay(event)? {
            return Ok(result);
        }
        if let Some(session_id) = event.writer_session_id.as_deref() {
            self.require_unfenced_transport(session_id)?;
            self.require_unfenced_durable_payment_session_v1(session_id)?;
        }
        let durable_admission = self.selected_durable_payment_admission_v1()?.cloned();
        if let Some(admission) = &durable_admission {
            if matches!(
                &event.mutation,
                AuthorityMutation::AcquireWriter(_)
                    | AuthorityMutation::ReserveAuthorization(_)
                    | AuthorityMutation::OwnerControl(OwnerControlRequest {
                        control: OwnerControl::ActivateWriter { .. },
                        ..
                    })
            ) {
                self.require_durable_payment_mutation_v1(
                    &admission.operation_id,
                    &event.mutation,
                    event.writer_session_id.as_deref(),
                    event.witness_time_ms,
                )?;
            } else if event.writer_session_id.is_some() {
                return Err(AuthorityError::Permission);
            }
        }
        // Bootstrap replay uses the same exact-attempt route as live admission.
        // Non-bootstrap events retain their own rules and remain readable under
        // later exclusion/quarantine; none become supported manual live history.
        if durable_admission.is_none()
            && matches!(
                &event.mutation,
                AuthorityMutation::AcquireWriter(_)
                    | AuthorityMutation::ReserveManualRosterConstructionV3(_)
                    | AuthorityMutation::ConsumeManualRosterConstructionV3(_)
                    | AuthorityMutation::ReserveManualRosterConstructionV2(_)
                    | AuthorityMutation::ConsumeManualRosterConstructionV2(_)
                    | AuthorityMutation::AdmitBornManualEnrollment(_)
                    | AuthorityMutation::AdmitBornManualEnrollmentV2(_)
                    | AuthorityMutation::AdmitBornManualRosterEnrollmentV2(_)
                    | AuthorityMutation::OwnerControl(OwnerControlRequest {
                        control: OwnerControl::ActivateWriter { .. },
                        ..
                    })
            )
        {
            if let Some(extension) = self.manual_roster_extension()? {
                self.require_manual_roster_bootstrap_scope_v2(
                    &extension.extension.digest()?,
                    &event.mutation,
                    event.witness_time_ms,
                )?;
            } else if let Some(extension) = self.manual_extension()? {
                self.require_manual_bootstrap_scope(
                    &extension.extension.digest()?,
                    &event.mutation,
                    event.witness_time_ms,
                )?;
            }
        }
        // Exact replay above stays historical evidence. No new execution
        // admission, session or issuance scope may be created after exclusion.
        self.require_account_use_for_new_mutation(&event.mutation)?;
        hash(&event.authenticated_certificate_digest)?;
        if self.snapshot.head.sequence >= MAX_EVENTS {
            return Err(AuthorityError::Limit);
        }
        if event.witness_time_ms < self.snapshot.last_witness_time_ms {
            return Err(AuthorityError::Expired);
        }
        let next_head = AuthorityHead {
            sequence: self.snapshot.head.sequence + 1,
            digest: digest(
                "wholepact:authority-append:v2",
                &(&self.snapshot.head, event),
            )?,
        };
        let result = match &event.mutation {
            AuthorityMutation::ClaimConstructionTransportV1(r) => {
                MutationResult::ConstructionTransportClaimedV1(Box::new(
                    self.apply_construction_transport_claim(r, event, &next_head)?,
                ))
            }
            AuthorityMutation::UseConstructionTransportV1(r) => {
                self.apply_construction_transport_use(r, event, &next_head)?
            }
            AuthorityMutation::ReserveManualRosterConstructionV3(r) => {
                MutationResult::ManualRosterConstructionReservedV3(Box::new(
                    self.apply_roster_construction_reservation_v3(r, event, &next_head)?,
                ))
            }
            AuthorityMutation::ConsumeManualRosterConstructionV3(r) => {
                MutationResult::ManualRosterConstructionConsumedV3(Box::new(
                    self.apply_roster_construction_consume_v3(r, event, &next_head)?,
                ))
            }
            AuthorityMutation::ReserveManualRosterConstructionV2(r) => {
                MutationResult::ManualRosterConstructionReservedV2(Box::new(
                    self.apply_roster_construction_reservation_v2(r, event, &next_head)?,
                ))
            }
            AuthorityMutation::ConsumeManualRosterConstructionV2(r) => {
                MutationResult::ManualRosterConstructionConsumedV2(Box::new(
                    self.apply_roster_construction_consume_v2(r, event, &next_head)?,
                ))
            }
            AuthorityMutation::AdmitBornManualRosterEnrollmentV2(r) => {
                MutationResult::ManualRosterEnrollmentAdmittedV2(Box::new(
                    self.apply_manual_roster_admission_v2(r, event, &next_head)?,
                ))
            }
            AuthorityMutation::AdmitBornManualEnrollmentV2(r) => {
                MutationResult::ManualEnrollmentAdmittedV2(Box::new(
                    self.apply_manual_admission_v2(r, event, &next_head)?,
                ))
            }
            AuthorityMutation::AdmitBornManualEnrollment(r) => {
                MutationResult::ManualEnrollmentAdmitted(Box::new(
                    self.apply_manual_admission(r, event, &next_head)?,
                ))
            }
            AuthorityMutation::ReserveBornOfflineV1(r) => {
                self.reserve_born_offline_v1(r, event, &next_head)?
            }
            AuthorityMutation::ReserveOfflineAuthorization(r) => {
                self.reserve_offline(r, event, &next_head)?
            }
            AuthorityMutation::AuthorizeAutomaticKeyUse(r) => {
                self.admit_automatic_key_use(r, event, &next_head)?
            }
            AuthorityMutation::QualifiedResolution(r) => {
                id(&r.operation_id)?;
                for v in [
                    &r.reservation_request_digest,
                    &r.final_transaction_id,
                    &r.final_transaction_digest,
                    &r.source_descriptor_digest,
                    &r.evidence_digest,
                ] {
                    hash(v)?;
                }
                if r.expected_head != self.snapshot.head
                    || self.resolution_source.as_ref() != Some(&r.source_descriptor_digest)
                {
                    return Err(AuthorityError::InvalidBinding);
                }
                let (_, _, result) = self
                    .operations
                    .get(&r.reservation_operation_id)
                    .ok_or(AuthorityError::InvalidBinding)?;
                let original =
                    ReservationView::from_result(result).ok_or(AuthorityError::InvalidBinding)?;
                if original.request_digest != r.reservation_request_digest
                    || self.final_transactions.get(&r.reservation_operation_id)
                        != Some(&(
                            r.final_transaction_digest.clone(),
                            r.final_transaction_id.clone(),
                        ))
                    || r.consumed_nullifiers.is_empty()
                    || r.consumed_nullifiers.len() > 256
                    || r.consumed_nullifiers.iter().collect::<BTreeSet<_>>().len()
                        != r.consumed_nullifiers.len()
                {
                    return Err(AuthorityError::InvalidBinding);
                }
                match &r.conflict {
                    None => {
                        if r.consumed_nullifiers.iter().collect::<BTreeSet<_>>()
                            != original
                                .inputs
                                .iter()
                                .map(|i| &i.nullifier)
                                .collect::<BTreeSet<_>>()
                        {
                            return Err(AuthorityError::InvalidBinding);
                        }
                    }
                    Some(candidate) => {
                        let descriptor = wholepact_chain::SubmissionDescriptor {
                            operation_id: original.operation_id.into(),
                            obligation_id: original.obligation_id.into(),
                            proposal_id: original.proposal_id.into(),
                            transaction_id: r.final_transaction_id.clone(),
                            bytes_sha256: r.final_transaction_digest.clone(),
                            expiry_height: original.transaction_expiry_height,
                            network: "testnet".into(),
                            consensus_branch_id: wholepact_chain::NU7_BRANCH_ID,
                        };
                        let inputs: Vec<_> = original
                            .inputs
                            .iter()
                            .map(|i| (i.action_index, i.nullifier.clone()))
                            .collect();
                        candidate
                            .validate_original(&descriptor, original.effects_digest, &inputs)
                            .map_err(|_| AuthorityError::InvalidBinding)?;
                        if original.network_profile_id != "ironwood-testnet-nu7-candidate"
                            || r.consumed_nullifiers != [candidate.nullifier.clone()]
                        {
                            return Err(AuthorityError::InvalidBinding);
                        }
                    }
                }
                hash(&r.inclusion_block_hash)?;
                if r.inclusion_block_height == 0 {
                    return Err(AuthorityError::InvalidBinding);
                }
                for n in &r.consumed_nullifiers {
                    hash(n)?;
                }
                if self.resolutions.contains_key(&r.reservation_operation_id) {
                    return Err(AuthorityError::Conflict);
                }
                let receipt = ResolutionReceipt {
                    record: r.clone(),
                    committed_head: next_head.clone(),
                };
                self.resolutions
                    .insert(r.reservation_operation_id.clone(), receipt.clone());
                self.recompute_exposure()?;
                MutationResult::ResolutionRecorded(Box::new(receipt))
            }
            AuthorityMutation::ReopenResolutions(r) => {
                id(&r.operation_id)?;
                if r.expected_head != self.snapshot.head {
                    return Err(AuthorityError::StaleHead);
                }
                self.resolutions.clear();
                self.recompute_exposure()?;
                self.snapshot.head = next_head.clone();
                self.snapshot.last_witness_time_ms = event.witness_time_ms;
                MutationResult::ResolutionsReopened(self.snapshot.clone())
            }
            AuthorityMutation::ReserveAuthorization(r) => {
                r.validate()?;
                if r.account_id != self.policy.account_id
                    || r.network_profile_id != self.policy.network_profile_id
                    || event.authenticated_certificate_digest
                        != self.snapshot.writer_certificate_digest
                {
                    return Err(AuthorityError::Permission);
                }
                self.fence(&r.expected_head, r.writer_epoch)?;
                if self.snapshot.writer_status != WriterStatus::Active {
                    return Err(AuthorityError::Inactive);
                }
                let now = event.witness_time_ms;
                let session = self
                    .snapshot
                    .active_writer_session
                    .as_ref()
                    .ok_or(AuthorityError::SessionRequired)?;
                if event.writer_session_id.as_deref() != Some(session.session_id.as_str())
                    || session.writer_epoch != r.writer_epoch
                    || session.writer_certificate_digest != event.authenticated_certificate_digest
                    || now >= session.expires_at_ms
                {
                    return Err(AuthorityError::SessionRequired);
                }
                if now < r.reviewed_at_ms
                    || now >= r.permit_expires_at_ms
                    || now >= self.policy.policy_expires_at_ms
                    || r.permit_expires_at_ms > self.policy.policy_expires_at_ms
                    || r.permit_expires_at_ms - r.reviewed_at_ms
                        > self.policy.maximum_permit_lifetime_ms
                {
                    return Err(AuthorityError::Expired);
                }
                // The NEW exact admission alone associates its original extension
                // reference. The immutable birth allowlist is never changed.
                if (!self.policy.enrollment_refs.contains(&r.enrollment_ref)
                    && durable_admission.is_none())
                    || !self.policy.agreement_ids.contains(&r.agreement_id)
                    || !self
                        .policy
                        .recipient_scope_digests
                        .contains(&r.recipient_scope_digest)
                    || r.maximum_debit_zatoshis > self.policy.per_operation_limit_zatoshis
                    || r.fee_share_zatoshis > self.policy.maximum_fee_share_zatoshis
                    || r.transaction_fee_zatoshis > self.policy.maximum_transaction_fee_zatoshis
                {
                    return Err(AuthorityError::PolicyDenied);
                }
                self.check_account_outstanding_limit(r.maximum_debit_zatoshis)?;
                self.check_automation_reservation(r, now, true)?;
                if self.authorizations.contains(&r.authorization_id)
                    || self.consents.contains(&r.original_consent_ref)
                {
                    return Err(AuthorityError::Conflict);
                }
                self.check_input_obligation_exclusions(
                    &r.obligation_id,
                    r.inputs
                        .iter()
                        .map(|i| (i.input_id.as_str(), i.nullifier.as_str())),
                )?;
                let debit = self
                    .snapshot
                    .outstanding_debit_zatoshis
                    .checked_add(r.maximum_debit_zatoshis)
                    .filter(|v| {
                        v.checked_add(self.snapshot.settled_debit_zatoshis)
                            .is_some_and(|total| total <= self.policy.aggregate_budget_zatoshis)
                    })
                    .ok_or(AuthorityError::BudgetExceeded)?;
                let selected = r.inputs.iter().try_fold(
                    self.snapshot.reserved_input_value_zatoshis,
                    |v, i| {
                        v.checked_add(i.value_zatoshis)
                            .filter(|v| *v <= MAX_MONEY)
                            .ok_or(AuthorityError::BudgetExceeded)
                    },
                )?;
                let permit = ReservationPermit {
                    protocol_version: PROTOCOL_VERSION,
                    witness_id: self.policy.witness_id.clone(),
                    policy_digest: self.snapshot.policy_digest.clone(),
                    request_digest: r.request_digest()?,
                    request: (**r).clone(),
                    committed_head: next_head.clone(),
                    reserved_at_ms: now,
                    account_outstanding_debit_zatoshis: debit,
                    account_reserved_input_value_zatoshis: selected,
                    writer_session_id: session.session_id.clone(),
                };
                permit.matches_request(r)?;
                // All validation and arithmetic finish before this pure state changes.
                self.snapshot.outstanding_debit_zatoshis = debit;
                self.snapshot.reserved_input_value_zatoshis = selected;
                self.snapshot.outstanding_reservations += 1;
                self.authorizations.insert(r.authorization_id.clone());
                self.consents.insert(r.original_consent_ref.clone());
                self.obligations.insert(r.obligation_id.clone());
                for input in &r.inputs {
                    self.input_ids.insert(input.input_id.clone());
                    self.nullifiers.insert(input.nullifier.clone());
                }
                MutationResult::Reserved(Box::new(permit))
            }
            AuthorityMutation::AuthorizeBornOfflineDispatchV1(r) => {
                MutationResult::BornOfflineDispatchAdmittedV1(Box::new(
                    self.apply_born_dispatch_v1(r, event, &next_head)?,
                ))
            }
            AuthorityMutation::AuthorizeDispatch(r) => {
                r.validate()?;
                if event.authenticated_certificate_digest != self.snapshot.writer_certificate_digest
                {
                    return Err(AuthorityError::Permission);
                }
                self.fence(&r.expected_head, r.writer_epoch)?;
                if self.snapshot.writer_status != WriterStatus::Active {
                    return Err(AuthorityError::Inactive);
                }
                let now = event.witness_time_ms;
                let session = self
                    .snapshot
                    .active_writer_session
                    .as_ref()
                    .ok_or(AuthorityError::SessionRequired)?;
                if event.writer_session_id.as_deref() != Some(session.session_id.as_str())
                    || session.writer_epoch != r.writer_epoch
                    || session.writer_certificate_digest != event.authenticated_certificate_digest
                    || now >= session.expires_at_ms
                {
                    return Err(AuthorityError::SessionRequired);
                }
                if now < r.reviewed_at_ms || now >= r.admission_expires_at_ms {
                    return Err(AuthorityError::Expired);
                }
                let (_, _, original) = self
                    .operations
                    .get(&r.reservation_operation_id)
                    .ok_or(AuthorityError::InvalidBinding)?;
                let reservation_view =
                    ReservationView::from_result(original).ok_or(AuthorityError::InvalidBinding)?;
                // Existing dispatch wire evidence embeds the original ONLINE
                // permit. No future origin may be coerced into this route.
                let MutationResult::Reserved(reservation) = original else {
                    return Err(AuthorityError::InvalidBinding);
                };
                if reservation_view.request_digest != r.reservation_request_digest
                    || reservation_view.account_id != r.account_id
                    || reservation_view.network_profile_id != r.network_profile_id
                    || reservation_view.transaction_expiry_height != r.transaction_expiry_height
                {
                    return Err(AuthorityError::InvalidBinding);
                }
                let final_binding = (
                    r.final_transaction_digest.clone(),
                    r.final_transaction_id.clone(),
                );
                if self
                    .final_transactions
                    .get(&r.reservation_operation_id)
                    .is_some_and(|old| old != &final_binding)
                {
                    return Err(AuthorityError::Conflict);
                }
                let admission = DispatchAdmission {
                    protocol_version: PROTOCOL_VERSION,
                    witness_id: self.policy.witness_id.clone(),
                    policy_digest: self.snapshot.policy_digest.clone(),
                    request_digest: r.request_digest()?,
                    request: r.clone(),
                    reservation: (**reservation).clone(),
                    committed_head: next_head.clone(),
                    admitted_at_ms: now,
                    writer_session_id: session.session_id.clone(),
                };
                admission.matches_request(r)?;
                self.final_transactions
                    .insert(r.reservation_operation_id.clone(), final_binding);
                // Admission is an immutable linearization point, not a remote
                // revocation lock, chain observation or reduction in exposure.
                MutationResult::DispatchAdmitted(Box::new(admission))
            }
            AuthorityMutation::AcquireWriter(r) => {
                for value in [&r.operation_id, &r.account_id, &r.network_profile_id] {
                    id(value)?;
                }
                hash(&r.session_id)?;
                hash(&r.reconciled_history_digest)?;
                r.disclosure.validate()?;
                self.fence(&r.expected_head, r.writer_epoch)?;
                if self.snapshot.writer_status == WriterStatus::Revoked {
                    return Err(AuthorityError::Inactive);
                }
                if self.snapshot.pending_writer_session.is_some()
                    || self.snapshot.active_writer_session.is_some()
                {
                    return Err(AuthorityError::SessionPending);
                }
                if r.disclosure.witness_id != self.policy.witness_id
                    || r.disclosure.account_id != self.policy.account_id
                    || r.disclosure.network_profile_id != self.policy.network_profile_id
                    || r.disclosure.policy_digest != self.snapshot.policy_digest
                    || r.reconciled_history_digest
                        != crate::session::history_digest(&self.snapshot)?
                {
                    return Err(AuthorityError::InvalidBinding);
                }
                let expires = event
                    .witness_time_ms
                    .checked_add(300_000)
                    .ok_or(AuthorityError::Expired)?
                    .min(self.policy.policy_expires_at_ms)
                    .min(
                        durable_admission
                            .as_ref()
                            .and_then(|r| match &r.control {
                                OwnerControl::AdmitDurablePaymentV1 { record } => {
                                    Some(record.terms.valid_until_ms)
                                }
                                _ => None,
                            })
                            .unwrap_or(u64::MAX),
                    );
                if expires <= event.witness_time_ms {
                    return Err(AuthorityError::Expired);
                }
                if self.sessions.contains_key(&r.session_id) {
                    return Err(AuthorityError::Conflict);
                }
                let receipt = WriterSessionReceipt {
                    session_id: r.session_id.clone(),
                    writer_certificate_digest: event.authenticated_certificate_digest.clone(),
                    writer_epoch: r.writer_epoch,
                    reconciled_head: r.expected_head.clone(),
                    reconciled_history_digest: r.reconciled_history_digest.clone(),
                    acquired_head: next_head.clone(),
                    expires_at_ms: expires,
                    acquired_at_ms: event.witness_time_ms,
                    disclosure: r.disclosure.clone(),
                };
                self.sessions.insert(r.session_id.clone(), receipt.clone());
                self.snapshot.pending_writer_session = Some(receipt.clone());
                MutationResult::WriterPending(receipt)
            }
            AuthorityMutation::ReportProgress(r) => {
                for value in [
                    &r.operation_id,
                    &r.account_id,
                    &r.network_profile_id,
                    &r.reservation_operation_id,
                ] {
                    id(value)?;
                }
                hash(&r.reservation_request_digest)?;
                hash(&r.evidence_digest)?;
                self.fence(&r.expected_head, r.writer_epoch)?;
                let (_, _, result) = self
                    .operations
                    .get(&r.reservation_operation_id)
                    .ok_or(AuthorityError::InvalidBinding)?;
                let permit =
                    ReservationView::from_result(result).ok_or(AuthorityError::InvalidBinding)?;
                if permit.request_digest != r.reservation_request_digest {
                    return Err(AuthorityError::InvalidBinding);
                }
                let session = self
                    .sessions
                    .get(
                        event
                            .writer_session_id
                            .as_deref()
                            .ok_or(AuthorityError::SessionRequired)?,
                    )
                    .ok_or(AuthorityError::SessionRequired)?;
                if session.writer_certificate_digest != event.authenticated_certificate_digest {
                    return Err(AuthorityError::Permission);
                }
                self.snapshot.head = next_head.clone();
                self.snapshot.last_witness_time_ms = event.witness_time_ms;
                // Progress records are explicitly non-resolving audit events.
                MutationResult::ProgressRecorded(self.snapshot.clone())
            }
            AuthorityMutation::OwnerControl(r) => {
                id(&r.operation_id)?;
                id(&r.account_id)?;
                id(&r.network_profile_id)?;
                hash(&r.expected_head.digest)?;
                if r.account_id != self.policy.account_id
                    || r.network_profile_id != self.policy.network_profile_id
                    || event.authenticated_certificate_digest
                        != self.policy.owner_certificate_digest
                {
                    return Err(AuthorityError::Permission);
                }
                self.fence(&r.expected_head, r.writer_epoch)?;
                match &r.control {
                    OwnerControl::AdmitDurablePaymentWithDeliveryV2 { .. } => {
                        if event.writer_session_id.is_some() {
                            return Err(AuthorityError::Permission);
                        }
                        self.validate_new_durable_delivery_admission_v2(r, event.witness_time_ms)?;
                    }
                    OwnerControl::AdmitDurablePaymentV1 { .. } => {
                        if event.writer_session_id.is_some() {
                            return Err(AuthorityError::Permission);
                        }
                        self.validate_new_durable_payment_admission_v1(r, event.witness_time_ms)?;
                        // Common tail closes only pointers; historical receipts,
                        // stored keys, construction fences and exposure stay intact.
                    }
                    OwnerControl::InstallBornOfflineArtifactsV1 { record } => {
                        if r.operation_id != record.binding.owner_operation_id()?
                            || r.expected_head != record.binding.expected_head
                        {
                            return Err(AuthorityError::InvalidBinding);
                        }
                        self.validate_new_born_offline_artifacts_v1(record, event.witness_time_ms)?;
                    }
                    OwnerControl::EnrollBornOfflineV1 { record } => {
                        if r.operation_id != record.enrollment.owner_operation_id()?
                            || r.expected_head != record.enrollment.expected_head
                        {
                            return Err(AuthorityError::InvalidBinding);
                        }
                        self.apply_born_offline_enrollment_v1(record, event.witness_time_ms)?;
                    }
                    OwnerControl::GrantConstructionTransportV1 { grant } => {
                        if r.operation_id != grant.operation_id
                            || r.expected_head != grant.expected_head
                        {
                            return Err(AuthorityError::InvalidBinding);
                        }
                        self.validate_construction_transport_grant(grant, event.witness_time_ms)?;
                        self.snapshot.transport_fences.get_or_insert(crate::construction_transport_handoff_v1::ConstructionTransportFenceSnapshotV1 { version:1, fenced_session_ids:BTreeSet::new() });
                    }
                    OwnerControl::ApproveManualRosterConstructionV3 { record } => {
                        let e = &self
                            .manual_roster_extension()?
                            .ok_or(AuthorityError::Permission)?
                            .extension;
                        if r.operation_id != record.approval.owner_operation_id(e)? {
                            return Err(AuthorityError::InvalidBinding);
                        }
                        self.validate_new_roster_construction_approval_v3(
                            record,
                            event.witness_time_ms,
                        )?;
                    }
                    OwnerControl::ApproveManualRosterConstructionV2 { record } => {
                        let e = &self
                            .manual_roster_extension()?
                            .ok_or(AuthorityError::Permission)?
                            .extension;
                        if r.operation_id != record.approval.owner_operation_id(e)? {
                            return Err(AuthorityError::InvalidBinding);
                        }
                        self.validate_new_roster_construction_approval_v2(
                            record,
                            event.witness_time_ms,
                        )?;
                    }
                    OwnerControl::ExtendManualRosterEnrollmentV2 { record } => {
                        if r.operation_id != record.extension.owner_operation_id()? {
                            return Err(AuthorityError::InvalidBinding);
                        }
                        self.validate_new_manual_roster_extension(record, event.witness_time_ms)?;
                    }
                    OwnerControl::ContinueManualRosterSessionV2 { record } => {
                        let extension = &self
                            .manual_roster_extension()?
                            .ok_or(AuthorityError::Permission)?
                            .extension;
                        if r.operation_id != record.continuation.owner_operation_id(extension)? {
                            return Err(AuthorityError::InvalidBinding);
                        }
                        self.validate_new_manual_roster_continuation_v2(
                            record,
                            event.witness_time_ms,
                        )?;
                    }
                    OwnerControl::ContinueManualEnrollmentSession { record } => {
                        let extension = &self
                            .manual_extension()?
                            .ok_or(AuthorityError::Permission)?
                            .extension;
                        if r.operation_id != record.continuation.owner_operation_id(extension)? {
                            return Err(AuthorityError::InvalidBinding);
                        }
                        self.validate_new_manual_continuation(record, event.witness_time_ms)?;
                        // The common owner-control tail clears only active/pending
                        // pointers. All old session receipts and SQL keys remain.
                    }
                    OwnerControl::ExtendManualEnrollment { record } => {
                        if r.operation_id != record.extension.owner_operation_id()? {
                            return Err(AuthorityError::InvalidBinding);
                        }
                        self.validate_new_manual_extension(record, event.witness_time_ms)?;
                    }
                    OwnerControl::PermanentlyExcludeAccount { exclusion } => {
                        if exclusion.operation_id != r.operation_id {
                            return Err(AuthorityError::InvalidBinding);
                        }
                        self.account_use_history.exclude(exclusion.clone())?;
                        self.snapshot.account_use_checkpoint =
                            self.account_use_history.checkpoint()?;
                    }
                    OwnerControl::EnrollOfflinePolicy {
                        policy,
                        expected_previous_digest,
                    } => self.set_offline_policy(
                        policy,
                        expected_previous_digest.as_deref(),
                        event.witness_time_ms,
                    )?,
                    OwnerControl::SetOfflinePolicyStatus {
                        enrollment_ref,
                        policy_digest,
                        status,
                    } => self.set_offline_status(enrollment_ref, policy_digest, *status)?,
                    OwnerControl::SetAutomationGrant {
                        grant,
                        account_policy,
                    } => self.set_automation_grant(grant, account_policy, event.witness_time_ms)?,
                    OwnerControl::ActivateWriter { session_id } => {
                        hash(session_id)?;
                        let pending = self
                            .snapshot
                            .pending_writer_session
                            .as_ref()
                            .ok_or(AuthorityError::SessionRequired)?;
                        if pending.session_id != *session_id
                            || pending.writer_epoch != self.snapshot.writer_epoch
                            || pending.writer_certificate_digest
                                != self.snapshot.writer_certificate_digest
                            || pending.acquired_head != r.expected_head
                            || event.witness_time_ms >= pending.expires_at_ms
                        {
                            return Err(AuthorityError::SessionRequired);
                        }
                        self.activated_sessions.insert(session_id.clone());
                        self.snapshot.active_writer_session =
                            self.snapshot.pending_writer_session.take();
                        self.snapshot.writer_status = WriterStatus::Active;
                    }
                    OwnerControl::EnrollResolutionSource {
                        source_descriptor_digest,
                    } => {
                        hash(source_descriptor_digest)?;
                        if self
                            .resolution_source
                            .as_ref()
                            .is_some_and(|s| s != source_descriptor_digest)
                        {
                            return Err(AuthorityError::Conflict);
                        }
                        self.resolution_source = Some(source_descriptor_digest.clone());
                    }
                    OwnerControl::Pause => self.snapshot.writer_status = WriterStatus::Paused,
                    OwnerControl::Revoke => self.snapshot.writer_status = WriterStatus::Revoked,
                    OwnerControl::RequireRecovery => {
                        self.snapshot.writer_status = WriterStatus::Quarantined
                    }
                    OwnerControl::ReplaceWriter {
                        writer_certificate_digest,
                    }
                    | OwnerControl::RecoverWriter {
                        writer_certificate_digest,
                        ..
                    } => {
                        if let OwnerControl::RecoverWriter {
                            inventory_digest, ..
                        } = &r.control
                        {
                            hash(inventory_digest)?;
                            if self
                                .admitted_certificates()
                                .contains(writer_certificate_digest.as_str())
                            {
                                return Err(AuthorityError::PolicyDenied);
                            }
                        }
                        hash(writer_certificate_digest)?;
                        if *writer_certificate_digest == self.policy.owner_certificate_digest
                            || *writer_certificate_digest == self.snapshot.writer_certificate_digest
                        {
                            return Err(AuthorityError::PolicyDenied);
                        }
                        let epoch = self
                            .snapshot
                            .writer_epoch
                            .checked_add(1)
                            .filter(|v| *v <= i64::MAX as u64)
                            .ok_or(AuthorityError::Limit)?;
                        self.snapshot.writer_certificate_digest = writer_certificate_digest.clone();
                        self.snapshot.writer_epoch = epoch;
                        self.snapshot.writer_status = WriterStatus::Active;
                    }
                }
                if !matches!(
                    &r.control,
                    OwnerControl::ActivateWriter { .. }
                        | OwnerControl::EnrollBornOfflineV1 { .. }
                        | OwnerControl::InstallBornOfflineArtifactsV1 { .. }
                        | OwnerControl::GrantConstructionTransportV1 { .. }
                        | OwnerControl::ApproveManualRosterConstructionV3 { .. }
                        | OwnerControl::ApproveManualRosterConstructionV2 { .. }
                        | OwnerControl::SetAutomationGrant { .. }
                        | OwnerControl::EnrollOfflinePolicy { .. }
                        | OwnerControl::SetOfflinePolicyStatus { .. }
                ) {
                    self.snapshot.pending_writer_session = None;
                    self.snapshot.active_writer_session = None;
                }
                self.snapshot.head = next_head.clone();
                self.snapshot.last_witness_time_ms = event.witness_time_ms;
                MutationResult::Controlled(self.snapshot.clone())
            }
        };
        self.snapshot.head = next_head;
        self.snapshot.last_witness_time_ms = event.witness_time_ms;
        self.operations.insert(
            event.mutation.operation_id().into(),
            (
                event.mutation.clone(),
                event.authenticated_certificate_digest.clone(),
                result.clone(),
            ),
        );
        Ok(result)
    }
    pub(crate) fn require_account_use_for_new_mutation(
        &self,
        mutation: &AuthorityMutation,
    ) -> Result<()> {
        let requires_use = match mutation {
            AuthorityMutation::ClaimConstructionTransportV1(_)
            | AuthorityMutation::UseConstructionTransportV1(_) => true,
            AuthorityMutation::ReserveManualRosterConstructionV3(_)
            | AuthorityMutation::ConsumeManualRosterConstructionV3(_)
            | AuthorityMutation::ReserveManualRosterConstructionV2(_)
            | AuthorityMutation::ConsumeManualRosterConstructionV2(_)
            | AuthorityMutation::AdmitBornManualEnrollment(_)
            | AuthorityMutation::AdmitBornManualEnrollmentV2(_)
            | AuthorityMutation::AdmitBornManualRosterEnrollmentV2(_) => true,
            AuthorityMutation::ReserveAuthorization(_)
            | AuthorityMutation::ReserveOfflineAuthorization(_)
            | AuthorityMutation::ReserveBornOfflineV1(_)
            | AuthorityMutation::AuthorizeAutomaticKeyUse(_)
            | AuthorityMutation::AuthorizeDispatch(_)
            | AuthorityMutation::AuthorizeBornOfflineDispatchV1(_)
            | AuthorityMutation::AcquireWriter(_) => true,
            AuthorityMutation::OwnerControl(r) => matches!(
                &r.control,
                OwnerControl::ActivateWriter { .. }
                    | OwnerControl::AdmitDurablePaymentV1 { .. }
                    | OwnerControl::AdmitDurablePaymentWithDeliveryV2 { .. }
                    | OwnerControl::EnrollBornOfflineV1 { .. }
                    | OwnerControl::InstallBornOfflineArtifactsV1 { .. }
                    | OwnerControl::GrantConstructionTransportV1 { .. }
                    | OwnerControl::ApproveManualRosterConstructionV3 { .. }
                    | OwnerControl::ApproveManualRosterConstructionV2 { .. }
                    | OwnerControl::ExtendManualEnrollment { .. }
                    | OwnerControl::ExtendManualRosterEnrollmentV2 { .. }
                    | OwnerControl::ContinueManualRosterSessionV2 { .. }
                    | OwnerControl::ContinueManualEnrollmentSession { .. }
                    | OwnerControl::SetOfflinePolicyStatus {
                        status: OfflineEnrollmentStatus::Active,
                        ..
                    }
                    | OwnerControl::EnrollOfflinePolicy { .. }
                    | OwnerControl::SetAutomationGrant { .. }
            ),
            _ => false,
        };
        if requires_use {
            self.account_use_history
                .require_not_permanently_excluded()?;
        }
        Ok(())
    }
    pub(crate) fn recompute_exposure(&mut self) -> Result<()> {
        self.obligations.clear();
        self.input_ids.clear();
        self.nullifiers.clear();
        let mut debit = 0u64;
        let mut selected = 0u64;
        let mut settled = 0u64;
        let mut count = 0u64;
        for (operation, (_, _, result)) in &self.operations {
            let Some(p) = ExposureView::from_result(result) else {
                continue;
            };
            // Consumption settles the debit; it does not replenish a lifetime
            // spending allowance. Reopening moves this same amount back to pending.
            if p.financial_resolution_allowed
                && self
                    .resolutions
                    .get(operation)
                    .is_some_and(|r| r.record.conflict.is_none())
            {
                settled = settled
                    .checked_add(p.maximum_debit_zatoshis)
                    .filter(|v| *v <= MAX_MONEY)
                    .ok_or(AuthorityError::Limit)?;
                self.obligations.insert(p.obligation_id.to_owned());
                continue;
            }
            // Canonical conflicts retain the original charged debit and input
            // reservations until a separately qualified all-alternative protocol
            // reconciles every required journal. No replacement is enabled here.
            debit = debit
                .checked_add(p.maximum_debit_zatoshis)
                .filter(|v| *v <= MAX_MONEY)
                .ok_or(AuthorityError::Limit)?;
            count += 1;
            self.obligations.insert(p.obligation_id.to_owned());
            for input in p.inputs() {
                selected = selected
                    .checked_add(input.value_zatoshis)
                    .filter(|v| *v <= MAX_MONEY)
                    .ok_or(AuthorityError::Limit)?;
                self.input_ids.insert(input.input_id.to_owned());
                self.nullifiers.insert(input.nullifier.to_owned());
            }
        }
        self.snapshot.outstanding_debit_zatoshis = debit;
        self.snapshot.settled_debit_zatoshis = settled;
        self.snapshot.reserved_input_value_zatoshis = selected;
        self.snapshot.outstanding_reservations = count;
        Ok(())
    }
    pub(crate) fn fence(&self, expected: &AuthorityHead, epoch: u64) -> Result<()> {
        if self.snapshot.writer_status == WriterStatus::Quarantined {
            return Err(AuthorityError::RecoveryRequired);
        }
        if expected != &self.snapshot.head || epoch != self.snapshot.writer_epoch {
            return Err(AuthorityError::StaleHead);
        }
        Ok(())
    }
}
