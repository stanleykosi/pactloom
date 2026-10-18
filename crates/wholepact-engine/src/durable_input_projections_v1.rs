//! Purpose-specific discovery coordination. This leaf is deliberately inactive
//! until native issuance, Store commit/backup guards and Host consent are wired.
//! A round and a candidate are inert state, not wallet or spending authority.
//! All Engine entry points are crate-private: a future exclusive private
//! coordinator facade must own the Engine/Store and never expose raw Mutation,
//! AgreementView or generic Engine access. No shared-Engine activation is safe.
use crate::{Access, ApiError, CandidateView, Engine, Envelope, Mutation, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use wholepact_core::{
    durable_input_projection_v1::{
        DurableInputProjectionIntentV1, DurableInputProjectionPurposeV1, DurableInputProjectionV1,
    },
    manual_construction::PreconstructionProvider,
    Amount, ParticipantAllocation, Proposal, ProposalManifest,
};
use wholepact_protocol::construction::durable_projection_shape_v1::candidate_from_retained_projections_v1;
use wholepact_signer_origin::{
    durable_input_projection_v1::{
        redisclosure::DurableInputProjectionDeliveryV1, DurableInputProjectionOutboxV1,
        DurableInputProjectionRequestV1,
    },
    AuthenticatedDurableInputProjectionV1,
};

const MAX_ROUNDS: usize = 4;

/// Non-authorizing organizer claims. The native signer independently joins the
/// actual account, original recipient policy and current source before export.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDiscoveryOwnerRequestV1 {
    pub account_id: String,
    pub participant_id: String,
    pub original_recipient_policy_digest: String,
    pub privacy_domain: String,
    pub contribution: Amount,
    pub maximum_fee_share: Amount,
    pub maximum_transaction_fee: Amount,
    pub historical_anchor_height: u32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableDiscoveryRoundRequestV1 {
    pub owners: Vec<DurableDiscoveryOwnerRequestV1>,
    pub provider: PreconstructionProvider,
    pub transaction_expiry_height: u32,
    pub minimum_confirmations: u32,
    pub maximum_scan_blocks: u32,
    pub protected_destination: String,
    pub retention_policy: String,
    pub valid_from_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
}

#[derive(Clone, Copy)]
pub enum DurableDiscoveryActionV1 {
    RetainDiscoveryIntent,
    ReadExactNativeRequest,
    RetainAuthenticatedProjection,
    ReadForExactCandidate,
    ReadForExactRecapture,
}

/// Current Host privacy permission, never a signer/account provenance issuer.
/// Production embeddings must hold the genuine foreground permission through
/// the complete synchronous operation; persisting a boolean is not sufficient.
pub trait LocalDurableDiscoveryConsentV1 {
    fn permits(
        &self,
        request: &DurableInputProjectionRequestV1,
        projection_digest: Option<&str>,
        action: DurableDiscoveryActionV1,
    ) -> bool;
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intake {
    signer_enrollment_reference: String,
    signer_process_instance: String,
    outbox: DurableInputProjectionOutboxV1,
    /// Optional fresh, independently approved delivery of this exact original
    /// outbox after a lost response. It never replaces the original request,
    /// projection, validity window or historical recipient provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    redelivery: Option<DurableInputProjectionDeliveryV1>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Round {
    version: u16,
    principal_id: String,
    metadata_origin: String,
    created_at: String,
    previous_candidate_id: Option<String>,
    requests: BTreeMap<String, DurableInputProjectionRequestV1>,
    intakes: BTreeMap<String, Intake>,
    frozen_manifest_digest: Option<String>,
}

/// Sanitized progress only. No input identifiers, values, addresses, source
/// endpoints, outbox bytes or retained permission claims are projected here.
#[derive(Serialize)]
pub struct DurableDiscoveryRoundSummaryV1 {
    pub candidate_id: String,
    pub retained_owner_count: usize,
    pub candidate_frozen: bool,
    pub cancellation_requested: bool,
    pub authorization_allowed: bool,
}

fn damaged() -> ApiError {
    ApiError::new("RECOVERY_REQUIRED", "Original durable discovery requests or authenticated receipt history are inconsistent; preserve the original journals")
}
fn denied() -> ApiError {
    ApiError::new("DISCLOSURE_DENIED", "Current exact discovery privacy permission, original encrypted destination, validity or coordination state is unavailable")
}
fn conflict() -> ApiError {
    ApiError::new("CONFLICT", "An immutable discovery round, owner receipt or candidate cannot be replaced; use a distinct explicit round")
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn now_seconds() -> Result<u64> {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).map_err(|_| denied())
}
fn summary(id: &str, round: &Round, cancelled: bool) -> DurableDiscoveryRoundSummaryV1 {
    DurableDiscoveryRoundSummaryV1 {
        candidate_id: id.into(),
        retained_owner_count: round.intakes.len(),
        candidate_frozen: round.frozen_manifest_digest.is_some(),
        cancellation_requested: cancelled,
        authorization_allowed: false,
    }
}

impl Round {
    /// Historical integrity only: no wall-clock freshness or current process is
    /// needed to decode already-admitted data. Old grant expiry is not erasure.
    fn validate(&self, id: &str) -> Result<()> {
        if self.version != 1
            || self.requests.len() != 2
            || self.intakes.len() > 2
            || self.principal_id.is_empty()
            || self.principal_id.len() > 128
            || !digest(&self.metadata_origin)
            || OffsetDateTime::parse(&self.created_at, &Rfc3339).is_err()
            || self
                .frozen_manifest_digest
                .as_ref()
                .is_some_and(|d| !digest(d))
        {
            return Err(damaged());
        }
        let accounts: Vec<_> = self.requests.keys().cloned().collect();
        let mut participants = BTreeSet::new();
        let mut operations = BTreeSet::new();
        let first = self.requests.values().next().ok_or_else(damaged)?;
        for (account, request) in &self.requests {
            request.validate().map_err(|_| damaged())?;
            let intent = &request.intent;
            if intent.proposal_id != id
                || intent.account_id != *account
                || intent.constructor_principal_id != self.principal_id
                || intent.local_reviewer_account_ids != accounts
                || intent.agreement != first.intent.agreement
                || intent.provider != first.intent.provider
                || intent.protected_destination != first.intent.protected_destination
                || intent.transaction_expiry_height != first.intent.transaction_expiry_height
                || !participants.insert(intent.participant_id.as_str())
                || !operations.insert(request.operation_id.as_str())
            {
                return Err(damaged());
            }
        }
        for (account, intake) in &self.intakes {
            intake.outbox.validate().map_err(|_| damaged())?;
            if let Some(delivery) = &intake.redelivery {
                delivery
                    .require_original(&intake.outbox)
                    .map_err(|_| damaged())?;
            }
            if Some(&intake.outbox.request) != self.requests.get(account)
                || intake.signer_enrollment_reference.is_empty()
                || intake.signer_enrollment_reference.len() > 128
                || !digest(&intake.signer_process_instance)
            {
                return Err(damaged());
            }
        }
        if self.frozen_manifest_digest.is_some() && self.intakes.len() != 2 {
            return Err(damaged());
        }
        Ok(())
    }
    fn candidate(&self, id: &str) -> Result<Proposal> {
        self.validate(id)?;
        if self.intakes.len() != 2 {
            return Err(ApiError::new(
                "MISSING_EVIDENCE",
                "Both original authenticated owner projections are required",
            ));
        }
        let projections = self
            .intakes
            .values()
            .map(|i| i.outbox.projection.clone())
            .collect::<Vec<_>>();
        let proposal = candidate_from_retained_projections_v1(&projections, &self.created_at)
            .map_err(|_| ApiError::new("EXACT_CANDIDATE_UNAVAILABLE", "The exact retained inputs cannot form this bounded candidate; no note reselection or fee-cap expansion was attempted"))?;
        let mut input = proposal.input().clone();
        input.previous_proposal_id = self.previous_candidate_id.clone();
        Proposal::validate(input).map_err(Into::into)
    }
}

pub(crate) fn validate_stored(envelope: &Envelope) -> Result<()> {
    if envelope.durable_input_projections_v1.len() > MAX_ROUNDS {
        return Err(damaged());
    }
    for (id, value) in &envelope.durable_input_projections_v1 {
        let round: Round = serde_json::from_value(value.clone()).map_err(|_| damaged())?;
        round.validate(id)?;
        let first = round.requests.values().next().ok_or_else(damaged)?;
        // Later terms editing may make a round stale, but never relabel history.
        if first.intent.agreement.agreement_id != envelope.view.agreement.agreement_id
            || first.intent.agreement.obligation_id != envelope.view.agreement.obligation_id
        {
            return Err(damaged());
        }
        let candidate = envelope
            .view
            .candidates
            .iter()
            .find(|c| c.candidate_id == *id);
        match (&round.frozen_manifest_digest, candidate) {
            (Some(expected), Some(candidate)) => {
                let derived = round.candidate(id)?;
                if expected != derived.manifest_digest()
                    || candidate.proposal != *derived.input()
                    || candidate.manifest_digest != *expected
                    || candidate.proposal_digest != derived.proposal_digest()
                {
                    return Err(damaged());
                }
            }
            (None, None) => {}
            _ => return Err(damaged()),
        }
    }
    Ok(())
}

impl Engine {
    /// Commit exact native requests before pairing or scanning either owner.
    /// IDs are domain-separated from the immutable command and actual agreement;
    /// callers do not select or retarget an existing candidate namespace entry.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_durable_discovery_v1(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        revision: u64,
        request: DurableDiscoveryRoundRequestV1,
        consent: &dyn LocalDurableDiscoveryConsentV1,
    ) -> Result<(Mutation, DurableDiscoveryRoundSummaryV1)> {
        self.require_current_agreement(agreement_id)?;
        let mut envelope = self.load(access, agreement_id)?;
        crate::planning::check_proposer(&envelope, access)?;
        let command = crate::context(
            access,
            key,
            "begin_durable_discovery_v1",
            agreement_id,
            Some(revision),
            &request,
        )?;
        let id = format!(
            "durable-candidate-v1-{}",
            crate::hash_domain(
                b"wholepact:engine-durable-discovery-candidate:v1\0",
                &serde_json::json!((
                    &command.principal_id,
                    &command.idempotency_key,
                    &command.request_digest
                )),
            )?
        );
        if let Some(replay) = self.replay(access, &command)? {
            let round = self.discovery_round(&envelope, &id)?;
            self.check_discovery(
                access,
                &envelope,
                &id,
                &round,
                consent,
                DurableDiscoveryActionV1::RetainDiscoveryIntent,
            )?;
            return Ok((
                replay,
                summary(&id, &round, envelope.view.cancellation_requested),
            ));
        }
        crate::candidates::check_revision(&envelope, revision)?;
        if request.owners.len() != 2 || envelope.durable_input_projections_v1.len() >= MAX_ROUNDS {
            return Err(ApiError::new("RESOURCE_EXHAUSTED", "Discovery requires exactly two owners and at most four immutable rounds per agreement"));
        }
        let accounts: Vec<_> = request
            .owners
            .iter()
            .map(|o| o.account_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if accounts.len() != 2 {
            return Err(denied());
        }
        let mut requests = BTreeMap::new();
        for owner in &request.owners {
            let intent = DurableInputProjectionIntentV1 {
                version: 1,
                purpose: DurableInputProjectionPurposeV1::DurablePlainFixedInputProjectionV1,
                agreement: envelope.view.agreement.clone(),
                proposal_id: id.clone(),
                account_id: owner.account_id.clone(),
                participant_id: owner.participant_id.clone(),
                original_recipient_policy_digest: owner.original_recipient_policy_digest.clone(),
                privacy_domain: owner.privacy_domain.clone(),
                contribution: owner.contribution,
                maximum_fee_share: owner.maximum_fee_share,
                maximum_transaction_fee: owner.maximum_transaction_fee,
                transaction_expiry_height: request.transaction_expiry_height,
                provider: request.provider.clone(),
                anchor_height: owner.historical_anchor_height,
                minimum_confirmations: request.minimum_confirmations,
                maximum_scan_blocks: request.maximum_scan_blocks,
                constructor_principal_id: access.principal_id.clone(),
                protected_destination: request.protected_destination.clone(),
                retention_policy: request.retention_policy.clone(),
                local_reviewer_account_ids: accounts.clone(),
                valid_from_unix_seconds: request.valid_from_unix_seconds,
                valid_until_unix_seconds: request.valid_until_unix_seconds,
            };
            let operation = crate::hash_domain(
                b"wholepact:engine-durable-discovery-owner:v1\0",
                &serde_json::json!((&id, &owner.account_id)),
            )?;
            let native = DurableInputProjectionRequestV1 {
                version: 1,
                operation_id: format!("durable-discovery-v1-{operation}"),
                intent,
            };
            native.validate().map_err(|_| denied())?;
            requests.insert(owner.account_id.clone(), native);
        }
        let round = Round {
            version: 1,
            principal_id: access.principal_id.clone(),
            metadata_origin: hex::encode(
                self.store
                    .verify_original_encrypted_destination(Path::new(
                        &request.protected_destination,
                    ))
                    .map_err(crate::store_error)?,
            ),
            created_at: OffsetDateTime::now_utc()
                .replace_nanosecond(0)
                .map_err(|_| denied())?
                .format(&Rfc3339)
                .map_err(|_| denied())?,
            previous_candidate_id: envelope
                .view
                .candidates
                .last()
                .map(|c| c.candidate_id.clone()),
            requests,
            intakes: BTreeMap::new(),
            frozen_manifest_digest: None,
        };
        self.check_discovery(
            access,
            &envelope,
            &id,
            &round,
            consent,
            DurableDiscoveryActionV1::RetainDiscoveryIntent,
        )?;
        if envelope.durable_input_projections_v1.contains_key(&id)
            || envelope
                .view
                .candidates
                .iter()
                .any(|c| c.candidate_id == id)
        {
            return Err(conflict());
        }
        put(&mut envelope, &id, &round)?;
        let result = summary(&id, &round, false);
        let mutation = self.commit(
            &command,
            agreement_id,
            revision,
            envelope,
            "durable_discovery_intent_retained",
        )?;
        Ok((mutation, result))
    }

    pub(crate) fn read_durable_discovery_request_v1(
        &self,
        access: &Access,
        agreement_id: &str,
        candidate_id: &str,
        account_id: &str,
        consent: &dyn LocalDurableDiscoveryConsentV1,
    ) -> Result<DurableInputProjectionRequestV1> {
        let envelope = self.load(access, agreement_id)?;
        let round = self.discovery_round(&envelope, candidate_id)?;
        self.check_discovery(
            access,
            &envelope,
            candidate_id,
            &round,
            consent,
            DurableDiscoveryActionV1::ReadExactNativeRequest,
        )?;
        round.requests.get(account_id).cloned().ok_or_else(denied)
    }

    /// The sole new-receipt admission path takes the nominal sealed installed
    /// signer observation. No public outbox/JSON overload exists.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn intake_durable_input_projection_v1(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        candidate_id: &str,
        revision: u64,
        disclosure: AuthenticatedDurableInputProjectionV1,
        consent: &dyn LocalDurableDiscoveryConsentV1,
    ) -> Result<Mutation> {
        let mut envelope = self.load(access, agreement_id)?;
        let mut round = self.discovery_round(&envelope, candidate_id)?;
        let outbox = disclosure.outbox();
        outbox.validate().map_err(|_| damaged())?;
        if let Some(delivery) = disclosure.redelivery() {
            delivery.require_original(outbox).map_err(|_| damaged())?;
        }
        let account = &outbox.request.intent.account_id;
        if round.requests.get(account) != Some(&outbox.request) {
            return Err(denied());
        }
        let intake = Intake {
            signer_enrollment_reference: disclosure.signer_enrollment_reference().into(),
            signer_process_instance: disclosure.signer_process_instance().into(),
            outbox: outbox.clone(),
            redelivery: disclosure.redelivery().cloned(),
        };
        let command = crate::context(
            access,
            key,
            "intake_durable_input_projection_v1",
            agreement_id,
            Some(revision),
            &(candidate_id, &round.metadata_origin, &intake),
        )?;
        self.check_discovery(
            access,
            &envelope,
            candidate_id,
            &round,
            consent,
            DurableDiscoveryActionV1::RetainAuthenticatedProjection,
        )?;
        if let Some(replay) = self.replay(access, &command)? {
            return Ok(replay);
        }
        crate::candidates::check_revision(&envelope, revision)?;
        if round.intakes.contains_key(account) || round.frozen_manifest_digest.is_some() {
            return Err(conflict());
        }
        round.intakes.insert(account.clone(), intake);
        self.check_discovery(
            access,
            &envelope,
            candidate_id,
            &round,
            consent,
            DurableDiscoveryActionV1::RetainAuthenticatedProjection,
        )?;
        put(&mut envelope, candidate_id, &round)?;
        self.commit(
            &command,
            agreement_id,
            revision,
            envelope,
            "durable_input_projection_admitted",
        )
    }

    /// Derive the entire immutable manifest from the original two receipts. No
    /// caller-supplied fee, input, return, target height or replacement is used.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn freeze_durable_discovery_candidate_v1(
        &self,
        access: &Access,
        key: &str,
        agreement_id: &str,
        candidate_id: &str,
        revision: u64,
        consent: &dyn LocalDurableDiscoveryConsentV1,
    ) -> Result<Mutation> {
        let mut envelope = self.load(access, agreement_id)?;
        let mut round = self.discovery_round(&envelope, candidate_id)?;
        self.check_discovery(
            access,
            &envelope,
            candidate_id,
            &round,
            consent,
            DurableDiscoveryActionV1::ReadForExactCandidate,
        )?;
        let proposal = round.candidate(candidate_id)?;
        let command = crate::context(
            access,
            key,
            "freeze_durable_discovery_candidate_v1",
            agreement_id,
            Some(revision),
            &(
                candidate_id,
                proposal.proposal_digest(),
                round
                    .intakes
                    .values()
                    .map(|i| &i.outbox.reference)
                    .collect::<Vec<_>>(),
            ),
        )?;
        if let Some(replay) = self.replay(access, &command)? {
            return Ok(replay);
        }
        crate::candidates::check_revision(&envelope, revision)?;
        crate::candidates::check_current_terms(&envelope.view, proposal.manifest())?;
        if round.frozen_manifest_digest.is_some()
            || envelope
                .view
                .candidates
                .iter()
                .any(|c| c.candidate_id == candidate_id)
            || envelope.view.candidates.last().map(|c| &c.candidate_id)
                != round.previous_candidate_id.as_ref()
            || envelope.view.candidates.len() >= crate::MAX_PROPOSALS
        {
            return Err(conflict());
        }
        self.check_discovery(
            access,
            &envelope,
            candidate_id,
            &round,
            consent,
            DurableDiscoveryActionV1::ReadForExactCandidate,
        )?;
        round.frozen_manifest_digest = Some(proposal.manifest_digest().into());
        envelope.view.candidates.push(CandidateView {
            candidate_id: candidate_id.into(),
            proposal: proposal.input().clone(),
            manifest_digest: proposal.manifest_digest().into(),
            proposal_digest: proposal.proposal_digest().into(),
            accounting: serde_json::to_value(proposal.accounting()).map_err(|_| damaged())?,
            reviews: vec![],
            proof_jobs: vec![],
        });
        put(&mut envelope, candidate_id, &round)?;
        envelope.view.progress = "preparing_proposal".into();
        self.commit(
            &command,
            agreement_id,
            revision,
            envelope,
            "durable_exact_candidate_terms_frozen",
        )
    }

    /// Explicit private metadata read for later exact-ID recapture. The returned
    /// DTO is historical data, not an export/scan permit or current unspentness
    /// proof. Production must keep checking this original source and consent at
    /// every later wallet/provider boundary and preserve EVERY commitment.
    pub(crate) fn read_durable_projection_for_recapture_v1(
        &self,
        access: &Access,
        agreement_id: &str,
        candidate_id: &str,
        account_id: &str,
        consent: &dyn LocalDurableDiscoveryConsentV1,
    ) -> Result<DurableInputProjectionV1> {
        let envelope = self.load(access, agreement_id)?;
        let round = self.discovery_round(&envelope, candidate_id)?;
        self.check_discovery(
            access,
            &envelope,
            candidate_id,
            &round,
            consent,
            DurableDiscoveryActionV1::ReadForExactRecapture,
        )?;
        if round.frozen_manifest_digest.is_none() {
            return Err(denied());
        }
        let intake = round.intakes.get(account_id).ok_or_else(damaged)?;
        Ok(intake.outbox.projection.clone())
    }

    pub(crate) fn durable_discovery_summaries_v1(
        &self,
        access: &Access,
        agreement_id: &str,
    ) -> Result<Vec<DurableDiscoveryRoundSummaryV1>> {
        let envelope = self.load(access, agreement_id)?;
        envelope
            .durable_input_projections_v1
            .keys()
            .map(|id| {
                let round = self.discovery_round(&envelope, id)?;
                Ok(summary(id, &round, envelope.view.cancellation_requested))
            })
            .collect()
    }

    fn discovery_round(&self, envelope: &Envelope, id: &str) -> Result<Round> {
        let round: Round = serde_json::from_value(
            envelope
                .durable_input_projections_v1
                .get(id)
                .ok_or_else(damaged)?
                .clone(),
        )
        .map_err(|_| damaged())?;
        round.validate(id)?;
        Ok(round)
    }

    fn check_discovery(
        &self,
        access: &Access,
        envelope: &Envelope,
        id: &str,
        round: &Round,
        consent: &dyn LocalDurableDiscoveryConsentV1,
        action: DurableDiscoveryActionV1,
    ) -> Result<()> {
        let check = || -> Result<()> {
            round.validate(id)?;
            self.require_current_agreement(&envelope.view.agreement.agreement_id)?;
            crate::planning::check_proposer(envelope, access)?;
            if round.principal_id != access.principal_id || envelope.view.cancellation_requested {
                return Err(denied());
            }
            check_round_terms(envelope, round)?;
            for request in round.requests.values() {
                request
                    .require_valid_at(now_seconds()?)
                    .map_err(|_| denied())?;
                let origin = self
                    .store
                    .verify_original_encrypted_destination(Path::new(
                        &request.intent.protected_destination,
                    ))
                    .map_err(crate::store_error)?;
                if hex::encode(origin) != round.metadata_origin {
                    return Err(denied());
                }
            }
            Ok(())
        };
        check()?;
        for (account, request) in &round.requests {
            let projected = round
                .intakes
                .get(account)
                .map(|i| i.outbox.projection_digest.as_str());
            if !consent.permits(request, projected, action) {
                return Err(denied());
            }
        }
        check()
    }
}

fn put(envelope: &mut Envelope, id: &str, round: &Round) -> Result<()> {
    round.validate(id)?;
    envelope.durable_input_projections_v1.insert(
        id.into(),
        serde_json::to_value(round).map_err(|_| damaged())?,
    );
    Ok(())
}

fn check_round_terms(envelope: &Envelope, round: &Round) -> Result<()> {
    if !envelope.view.roster_selected {
        return Err(denied());
    }
    let first = round.requests.values().next().ok_or_else(damaged)?;
    let participants = round
        .requests
        .values()
        .map(|r| {
            let i = &r.intent;
            Ok(ParticipantAllocation {
                participant_id: i.participant_id.clone(),
                account_id: i.account_id.clone(),
                contribution: i.contribution,
                fee_share: Amount::ZERO,
                fee_cap: i.maximum_fee_share,
                maximum_net_debit: i.maximum_selection_debit()?,
                charges: vec![],
            })
        })
        .collect::<Result<Vec<_>>>()?;
    // The maintained current-terms checker validates selected roster, exact
    // contribution, fee/debit caps, expiry and absence of conditions. This is
    // NOT Proposal::validate and makes no claim of complete transaction inputs.
    crate::candidates::check_current_terms(
        &envelope.view,
        &ProposalManifest {
            agreement: first.intent.agreement.clone(),
            participants,
            inputs: vec![],
            outputs: vec![],
            transaction_fee: Amount::ZERO,
            expiry_height: first.intent.transaction_expiry_height,
        },
    )
}
