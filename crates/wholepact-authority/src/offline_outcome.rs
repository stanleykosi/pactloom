//! Durable single-outcome emission fence. No production constructor or endpoint.
//! A selected capability may have escaped even if there is no outbox ciphertext.
//! Selection is irreversible and cannot be replayed to manufacture another token.
use crate::{
    offline::*,
    offline_export::OfflineAdmissionExportPlan,
    offline_retry::{self, OfflineOriginalBridge, RetainedOfflineOriginal},
    *,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

pub(crate) const OFFLINE_OUTCOME_SCHEMA: &str = include_str!("offline_outcome_schema.sql");

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OfflineAdmissionControlOutcome {
    /// The exact original request never reserved exposure, and may never do so.
    NoAdmission,
    /// Delivery was abandoned before any admission export capability escaped.
    /// ALL committed exposure/exclusions remain; unknown remote copies are not cleared.
    ExposureRetained { admission_digest: String },
}

/// Pure portable descriptor. Neither deserialization nor validation authenticates
/// the witness, establishes a terminal decision, or creates financial authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineAdmissionControl {
    pub schema_version: u16,
    pub witness_id: String,
    pub witness_policy_digest: String,
    pub witness_transport_key_digest: String,
    pub request_digest: String,
    pub request: ReserveOfflineAuthorization,
    pub prepared_record_digest: String,
    pub authenticated_receipt_digest: String,
    pub original_export_plan_digest: String,
    pub original_sequence: u64,
    pub selected_head: AuthorityHead,
    pub selected_at_ms: u64,
    pub outcome: OfflineAdmissionControlOutcome,
}
impl OfflineAdmissionControl {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        self.request.validate()?;
        id(&self.witness_id)?;
        for value in [
            &self.witness_policy_digest,
            &self.witness_transport_key_digest,
            &self.request_digest,
            &self.prepared_record_digest,
            &self.authenticated_receipt_digest,
            &self.original_export_plan_digest,
            &self.selected_head.digest,
        ] {
            hash(value)?;
        }
        if let OfflineAdmissionControlOutcome::ExposureRetained { admission_digest } = &self.outcome
        {
            hash(admission_digest)?;
        }
        if self.request_digest != self.request.request_digest()?
            || self.original_sequence == 0
            || self.original_sequence > i64::MAX as u64
            || self.selected_head.sequence > MAX_EVENTS
            || self.selected_at_ms < self.request.requested_at_ms
            || self.selected_at_ms > i64::MAX as u64
        {
            return Err(AuthorityError::InvalidBinding);
        }
        encode(self)?;
        Ok(())
    }
    pub fn matches_request(&self, request: &ReserveOfflineAuthorization) -> Result<()> {
        self.validate()?;
        if self.request != *request {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    /// New current CONTROL window on the original never-emitted allocation.
    /// This does not modify or renew the original admission plan or deadline.
    pub fn validate_export_plan(&self, plan: &OfflineAdmissionExportPlan) -> Result<()> {
        self.validate()?;
        plan.validate()?;
        let (issued, expires) =
            offline_retry::window(plan.issued_at_unix_seconds, plan.expires_at_unix_seconds)?;
        let t = &self.request.intent.terms;
        if plan.sequence != self.original_sequence
            || plan.sender_id != format!("offline-admission:{}", t.offline_policy_digest)
            || plan.recipient_id != format!("offline-admission:{}", t.offline_signer_key_digest)
            || plan.sender_key_fingerprint != self.witness_transport_key_digest
            || plan.recipient_key_fingerprint != t.offline_signer_key_digest
            || issued
                != self
                    .selected_at_ms
                    .checked_add(999)
                    .ok_or(AuthorityError::InvalidBinding)?
                    / 1000
                    * 1000
            || self.selected_at_ms >= expires
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn control_digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:offline-admission-control:v1", self)
    }
}

/// An opaque once-selected admission outcome. No Clone, Deserialize or public
/// constructor. Only offline_export's private from_selected can consume it.
pub(crate) struct SelectedOfflineAdmission {
    descriptor: OfflineAuthorizationAdmission,
    plan: OfflineAdmissionExportPlan,
}
impl SelectedOfflineAdmission {
    pub(crate) fn into_parts(self) -> (OfflineAuthorizationAdmission, OfflineAdmissionExportPlan) {
        (self.descriptor, self.plan)
    }
}

/// Opaque terminal-control export capability. Only a successful durable outcome
/// fence constructs it. It grants disclosure of that control, never signing.
pub struct CommittedOfflineControlExport {
    descriptor: OfflineAdmissionControl,
    plan: OfflineAdmissionExportPlan,
}
impl CommittedOfflineControlExport {
    pub fn descriptor(&self) -> &OfflineAdmissionControl {
        &self.descriptor
    }
    pub fn export_plan(&self) -> &OfflineAdmissionExportPlan {
        &self.plan
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeRecord {
    schema_version: u16,
    prepared_record_digest: String,
    authenticated_receipt_digest: String,
    request_digest: String,
    original_export_plan_digest: String,
    selected_head: AuthorityHead,
    selected_at_ms: u64,
    emission_may_have_started: bool,
    plan: OfflineAdmissionExportPlan,
    artifact: OutcomeArtifact,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "descriptor",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum OutcomeArtifact {
    Admission(OfflineAuthorizationAdmission),
    Control(OfflineAdmissionControl),
}
impl OutcomeRecord {
    fn kind(&self) -> &'static str {
        match &self.artifact {
            OutcomeArtifact::Admission(_) => "admission",
            OutcomeArtifact::Control(c) => match &c.outcome {
                OfflineAdmissionControlOutcome::NoAdmission => "no_admission",
                OfflineAdmissionControlOutcome::ExposureRetained { .. } => "exposure_retained",
            },
        }
    }
    fn decision_digest(&self) -> Result<String> {
        if self.schema_version != 1 || !self.emission_may_have_started {
            return Err(AuthorityError::CorruptHistory);
        }
        for value in [
            &self.prepared_record_digest,
            &self.authenticated_receipt_digest,
            &self.request_digest,
            &self.original_export_plan_digest,
            &self.selected_head.digest,
        ] {
            hash(value)?;
        }
        self.plan.validate()?;
        match &self.artifact {
            OutcomeArtifact::Admission(a) => self.plan.matches_commit(a)?,
            OutcomeArtifact::Control(c) => c.validate_export_plan(&self.plan)?,
        }
        digest("wholepact:offline-single-outcome:v1", self)
    }
}

impl OfflineOriginalBridge<'_> {
    /// Parent's sealed composition calls this only after the original authority
    /// event committed. A prior fence refuses reissuance even if outbox is absent.
    #[cfg(all(feature = "offline-witness-owner", target_os = "linux"))]
    pub(crate) fn select_admission_export_current_v1(
        &self,
        operation: &str,
        current: &crate::offline_witness_v1::CurrentOfflineWitnessWindowV1,
    ) -> Result<CommittedOfflineAdmissionExport> {
        let selected = select_admission_outcome_timed(
            self.journal,
            self.peer,
            operation,
            current.check()?,
            Some(current),
        )?;
        Ok(crate::offline_export::CommittedOfflineAdmissionExport::from_selected(selected))
    }
    pub fn select_admission_export(
        &self,
        operation: &str,
        now: u64,
    ) -> Result<crate::offline_export::CommittedOfflineAdmissionExport> {
        let selected = select_admission_outcome(self.journal, self.peer, operation, now)?;
        Ok(crate::offline_export::CommittedOfflineAdmissionExport::from_selected(selected))
    }
    /// Explicit terminal transport outcome, never cancellation of exposure.
    /// plan.sequence must equal the original allocated sequence; all plan fields
    /// are fixed in the fence before this one capability can escape.
    pub fn select_control_export(
        &self,
        operation: &str,
        plan: OfflineAdmissionExportPlan,
        now: u64,
    ) -> Result<CommittedOfflineControlExport> {
        select_control_outcome(self.journal, self.peer, operation, plan, now)
    }
}

pub(crate) fn select_admission_outcome(
    journal: &AuthorityJournal,
    peer: &str,
    operation: &str,
    now: u64,
) -> Result<SelectedOfflineAdmission> {
    select_admission_outcome_timed(journal, peer, operation, now, None)
}
pub(crate) fn select_admission_outcome_timed(
    journal: &AuthorityJournal,
    peer: &str,
    operation: &str,
    now: u64,
    current: Option<&crate::offline_witness_v1::CurrentOfflineWitnessWindowV1>,
) -> Result<SelectedOfflineAdmission> {
    journal.require_born_mutation_current()?;
    id(operation)?;
    let c = journal
        .connection
        .lock()
        .map_err(|_| AuthorityError::Storage)?;
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
    let now = match current {
        Some(window) => window.check()?,
        None => now,
    };
    let (ledger, original) = load_for_selection(&tx, peer, operation, now)?;
    if current.is_some() {
        offline_retry::gate(&tx, peer, original.request(), now)?;
    }
    let receipt = original
        .receipt
        .as_ref()
        .ok_or(AuthorityError::Authentication)?;
    offline_retry::require_inbox_acceptance(&tx, &original)?;
    let prepared = original.prepared_record_digest()?;
    require_unselected(&tx, &prepared)?;
    // Derive committed admission from authenticated append history, not a caller DTO.
    let (mutation, original_peer, result) = ledger
        .operations
        .get(operation)
        .ok_or(AuthorityError::InvalidBinding)?;
    let (
        AuthorityMutation::ReserveOfflineAuthorization(body),
        MutationResult::OfflineReserved(admission),
    ) = (mutation, result)
    else {
        return Err(AuthorityError::Conflict);
    };
    if original_peer != peer
        || body.request != *original.request()
        || admission.request != *original.request()
    {
        return Err(AuthorityError::Conflict);
    }
    // A legacy descriptor-only event with no source link must never be upgraded.
    let event_bytes = Zeroizing::new(tx.query_row(
        "SELECT CASE WHEN length(payload)<=262144 THEN payload ELSE NULL END FROM authority_events WHERE operation_id=?1",
        [operation], |r| r.get::<_,Vec<u8>>(0))?);
    let event: policy::Event = decode(&event_bytes)?;
    let linked = event
        .original_request_link
        .as_ref()
        .ok_or(AuthorityError::Authentication)?;
    let AuthorityMutation::ReserveOfflineAuthorization(event_record) = &event.mutation else {
        return Err(AuthorityError::CorruptHistory);
    };
    let policy = ledger
        .offline_policies
        .get(&original.request().intent.terms.offline_policy_digest)
        .ok_or(AuthorityError::CorruptHistory)?;
    offline_retry::verify_original_event_link(
        &tx,
        event_record,
        linked,
        policy,
        event
            .writer_session_id
            .as_deref()
            .ok_or(AuthorityError::CorruptHistory)?,
        event.witness_time_ms,
    )?;
    if event_record.as_ref() != body.as_ref()
        || event.authenticated_certificate_digest != peer
        || event.witness_time_ms != admission.reserved_at_ms
    {
        return Err(AuthorityError::CorruptHistory);
    }
    let plan = receipt.export_plan.clone();
    plan.matches_commit(admission)?;
    let (issued, expires) =
        offline_retry::window(plan.issued_at_unix_seconds, plan.expires_at_unix_seconds)?;
    if now < issued || now >= expires {
        return Err(AuthorityError::Expired);
    }
    let record = OutcomeRecord {
        schema_version: 1,
        prepared_record_digest: prepared,
        authenticated_receipt_digest: receipt.receipt_digest()?,
        request_digest: original.request().request_digest()?,
        original_export_plan_digest: plan.plan_digest()?,
        selected_head: ledger.snapshot.head,
        selected_at_ms: now,
        emission_may_have_started: true,
        plan: plan.clone(),
        artifact: OutcomeArtifact::Admission((**admission).clone()),
    };
    persist_outcome(&tx, &record)?;
    if let Some(window) = current {
        let fresh = window.check()?;
        load_for_selection(&tx, peer, operation, fresh)?;
        let checked = offline_retry::gate(&tx, peer, original.request(), fresh)?;
        window.check_after_replay(&checked, original.request())?;
    }
    tx.commit()?; // A token must not leave this function before this durable fence.
    Ok(SelectedOfflineAdmission {
        descriptor: (**admission).clone(),
        plan,
    })
}

pub(crate) fn select_control_outcome(
    journal: &AuthorityJournal,
    peer: &str,
    operation: &str,
    plan: OfflineAdmissionExportPlan,
    now: u64,
) -> Result<CommittedOfflineControlExport> {
    journal.require_born_mutation_current()?;
    id(operation)?;
    let c = journal
        .connection
        .lock()
        .map_err(|_| AuthorityError::Storage)?;
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
    let (ledger, original) = load_for_selection(&tx, peer, operation, now)?;
    let receipt = original
        .receipt
        .as_ref()
        .ok_or(AuthorityError::Authentication)?;
    let prepared = original.prepared_record_digest()?;
    require_unselected(&tx, &prepared)?;
    let policy = ledger
        .offline_policies
        .get(&original.request().intent.terms.offline_policy_digest)
        .ok_or(AuthorityError::PolicyDenied)?;
    let outcome = match ledger.operations.get(operation) {
        None => {
            // Do not label this allocation NoAdmission when the same original
            // intent/authorization already reserved under a different operation.
            let intent_digest = original.request().intent.intent_digest()?;
            for (mutation, _, _) in ledger.operations.values() {
                if let AuthorityMutation::ReserveOfflineAuthorization(body) = mutation {
                    if body.request.intent.intent_id == original.request().intent.intent_id
                        || body.request.intent.terms.authorization_id
                            == original.request().intent.terms.authorization_id
                        || body.request.intent.intent_digest()? == intent_digest
                    {
                        return Err(AuthorityError::Conflict);
                    }
                }
            }
            OfflineAdmissionControlOutcome::NoAdmission
        }
        Some((
            AuthorityMutation::ReserveOfflineAuthorization(body),
            original_peer,
            MutationResult::OfflineReserved(admission),
        )) if body.request == *original.request()
            && original_peer == peer
            && admission.request == *original.request() =>
        {
            OfflineAdmissionControlOutcome::ExposureRetained {
                admission_digest: digest(
                    "wholepact:offline-committed-admission:v1",
                    admission.as_ref(),
                )?,
            }
        }
        _ => return Err(AuthorityError::Conflict),
    };
    if plan.message_id == receipt.export_plan.message_id {
        return Err(AuthorityError::Conflict);
    }
    let control = OfflineAdmissionControl {
        schema_version: 1,
        witness_id: ledger.policy.witness_id.clone(),
        witness_policy_digest: ledger.policy.policy_digest()?,
        witness_transport_key_digest: policy.witness_transport_key_digest.clone(),
        request_digest: original.request().request_digest()?,
        request: original.request().clone(),
        prepared_record_digest: prepared.clone(),
        authenticated_receipt_digest: receipt.receipt_digest()?,
        original_export_plan_digest: receipt.export_plan.plan_digest()?,
        original_sequence: receipt.export_plan.sequence,
        selected_head: ledger.snapshot.head.clone(),
        selected_at_ms: now,
        outcome,
    };
    control.validate_export_plan(&plan)?;
    let record = OutcomeRecord {
        schema_version: 1,
        prepared_record_digest: prepared,
        authenticated_receipt_digest: receipt.receipt_digest()?,
        request_digest: control.request_digest.clone(),
        original_export_plan_digest: control.original_export_plan_digest.clone(),
        selected_head: ledger.snapshot.head,
        selected_at_ms: now,
        emission_may_have_started: true,
        plan: plan.clone(),
        artifact: OutcomeArtifact::Control(control.clone()),
    };
    // NoAdmission and its permanent original-operation gate share this commit.
    // ExposureRetained writes no authority event and releases no budget/input.
    persist_outcome(&tx, &record)?;
    tx.commit()?;
    Ok(CommittedOfflineControlExport {
        descriptor: control,
        plan,
    })
}

/// Mandatory inside the reservation event's immediate transaction. A control
/// choice permanently prohibits admitting this original operation. No race window.
pub(crate) fn ensure_admission_allowed(c: &Connection, prepared: &str) -> Result<()> {
    if let Some(record) = read_outcome(c, prepared)? {
        if matches!(record.artifact, OutcomeArtifact::Control(_)) {
            return Err(AuthorityError::Conflict);
        }
    }
    Ok(())
}
pub(crate) fn verify_no_admission_not_selected(c: &Connection, prepared: &str) -> Result<()> {
    if let Some(record) = read_outcome(c, prepared)? {
        if matches!(
            record.artifact,
            OutcomeArtifact::Control(OfflineAdmissionControl {
                outcome: OfflineAdmissionControlOutcome::NoAdmission,
                ..
            })
        ) {
            return Err(AuthorityError::CorruptHistory);
        }
    }
    Ok(())
}
fn require_unselected(c: &Connection, prepared: &str) -> Result<()> {
    if read_outcome(c, prepared)?.is_some() {
        // Even same-outcome retry cannot mint another capability. Exact existing
        // outbox ciphertext may be recovered separately; absent bytes stop here.
        return Err(AuthorityError::Uncertain);
    }
    Ok(())
}
fn persist_outcome(tx: &Transaction<'_>, record: &OutcomeRecord) -> Result<()> {
    let payload = encode(record)?;
    offline_retry::ensure_capacity(tx, payload.len(), 0, false)?;
    tx.execute(
        "INSERT INTO authority_offline_outcomes VALUES(?1,?2,?3,1,?4)",
        params![
            record.prepared_record_digest,
            record.kind(),
            record.decision_digest()?,
            &*payload
        ],
    )?;
    Ok(())
}
fn read_outcome(c: &Connection, prepared: &str) -> Result<Option<OutcomeRecord>> {
    hash(prepared)?;
    let raw: Option<(String,String,i64,Vec<u8>)> = c.query_row(
        "SELECT outcome_kind,decision_digest,emission_may_have_started,CASE WHEN length(payload)<=262144 THEN payload ELSE NULL END FROM authority_offline_outcomes WHERE prepared_digest=?1",
        [prepared], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let Some((kind, expected, emitted, payload)) = raw else {
        return Ok(None);
    };
    let payload = Zeroizing::new(payload);
    let record: OutcomeRecord = decode(&payload)?;
    if emitted != 1
        || record.prepared_record_digest != prepared
        || record.kind() != kind
        || record.decision_digest()? != expected
        || encode(&record)?.as_slice() != payload.as_slice()
    {
        return Err(AuthorityError::CorruptHistory);
    }
    Ok(Some(record))
}

/// This is NOT channel authentication. The unconstructible configured bridge
/// handle's future factory must provide that. Recheck current protected lifecycle
/// under the same lock as selection. Original request/export expiry and offline
/// enrollment pause do not prevent nonfinancial terminal control; old pinned
/// policy remains exact and no signing authority results.
fn load_for_selection(
    c: &Connection,
    peer: &str,
    operation: &str,
    now: u64,
) -> Result<(policy::Ledger, RetainedOfflineOriginal)> {
    crate::journal::authenticate_admission(c, peer)?;
    let ledger = crate::journal::load(c)?;
    let original =
        offline_retry::read_original(c, operation)?.ok_or(AuthorityError::InvalidBinding)?;
    let t = &original.request().intent.terms;
    ledger.authenticate_read(peer, &t.account_id, &t.network_profile_id)?;
    if ledger.snapshot.writer_status == WriterStatus::Quarantined {
        return Err(AuthorityError::RecoveryRequired);
    }
    if ledger.snapshot.writer_status != WriterStatus::Active
        || ledger.snapshot.writer_certificate_digest != peer
        || original.original.writer_certificate_digest != peer
        || original.request().writer_epoch != ledger.snapshot.writer_epoch
    {
        return Err(AuthorityError::Inactive);
    }
    let session = ledger
        .snapshot
        .active_writer_session
        .as_ref()
        .ok_or(AuthorityError::SessionRequired)?;
    ledger.require_unfenced_transport(&session.session_id)?;
    ledger.require_unfenced_transport(&original.original.writer_session_id)?;
    if session.session_id != original.original.writer_session_id
        || session.writer_certificate_digest != peer
        || session.writer_epoch != ledger.snapshot.writer_epoch
        || now >= session.expires_at_ms
        || !ledger.activated_sessions.contains(&session.session_id)
    {
        return Err(AuthorityError::SessionRequired);
    }
    if now < ledger.snapshot.last_witness_time_ms {
        return Err(AuthorityError::Expired);
    }
    let policy = ledger
        .offline_policies
        .get(&t.offline_policy_digest)
        .ok_or(AuthorityError::PolicyDenied)?;
    offline_retry::verify_retained(&original, policy)?;
    if now < original.original.prepared_at_ms
        || original
            .receipt
            .as_ref()
            .is_some_and(|r| now < r.authenticated_at_ms)
    {
        return Err(AuthorityError::Expired);
    }
    Ok((ledger, original))
}

#[cfg(test)]
#[path = "offline_outcome_tests.rs"]
mod tests;

pub(crate) fn verify_retained_outcome(
    c: &Connection,
    ledger: &policy::Ledger,
    original: &RetainedOfflineOriginal,
) -> Result<()> {
    let Some(record) = read_outcome(c, &original.prepared_record_digest()?)? else {
        return Ok(());
    };
    let receipt = original
        .receipt
        .as_ref()
        .ok_or(AuthorityError::CorruptHistory)?;
    if record.authenticated_receipt_digest != receipt.receipt_digest()?
        || record.request_digest != original.request().request_digest()?
        || record.original_export_plan_digest != receipt.export_plan.plan_digest()?
        || record.selected_at_ms < receipt.authenticated_at_ms
        || record.selected_head.sequence > ledger.snapshot.head.sequence
    {
        return Err(AuthorityError::CorruptHistory);
    }
    let (head, time) = if record.selected_head.sequence == 0 {
        (ledger.policy.policy_digest()?, 0)
    } else {
        let (head, bytes): (String,Vec<u8>) = c.query_row(
            "SELECT head,CASE WHEN length(payload)<=262144 THEN payload ELSE NULL END FROM authority_events WHERE sequence=?1",
            [record.selected_head.sequence], |r| Ok((r.get(0)?,r.get(1)?)))?;
        let bytes = Zeroizing::new(bytes);
        let event: policy::Event = decode(&bytes)?;
        (head, event.witness_time_ms)
    };
    if record.selected_head.digest != head || record.selected_at_ms < time {
        return Err(AuthorityError::CorruptHistory);
    }
    match &record.artifact {
        OutcomeArtifact::Admission(admission) => {
            offline_retry::require_inbox_acceptance(c, original)?;
            if record.plan != receipt.export_plan {
                return Err(AuthorityError::CorruptHistory);
            }
            let Some((
                AuthorityMutation::ReserveOfflineAuthorization(body),
                peer,
                MutationResult::OfflineReserved(actual),
            )) = ledger.operations.get(&original.request().operation_id)
            else {
                return Err(AuthorityError::CorruptHistory);
            };
            if body.request != *original.request()
                || actual.as_ref() != admission
                || peer != &original.original.writer_certificate_digest
            {
                return Err(AuthorityError::CorruptHistory);
            }
            let bytes = Zeroizing::new(c.query_row(
                "SELECT CASE WHEN length(payload)<=262144 THEN payload ELSE NULL END FROM authority_events WHERE operation_id=?1",
                [&original.request().operation_id], |r| r.get::<_,Vec<u8>>(0))?);
            let event: policy::Event = decode(&bytes)?;
            if event.original_request_link.is_none() {
                return Err(AuthorityError::CorruptHistory);
            }
        }
        OutcomeArtifact::Control(control) => {
            let policy = ledger
                .offline_policies
                .get(&original.request().intent.terms.offline_policy_digest)
                .ok_or(AuthorityError::CorruptHistory)?;
            if control.request != *original.request()
                || control.witness_id != ledger.policy.witness_id
                || control.witness_policy_digest != ledger.policy.policy_digest()?
                || control.witness_transport_key_digest != policy.witness_transport_key_digest
                || control.prepared_record_digest != record.prepared_record_digest
                || control.authenticated_receipt_digest != record.authenticated_receipt_digest
                || control.original_export_plan_digest != record.original_export_plan_digest
                || control.original_sequence != receipt.export_plan.sequence
                || control.selected_head != record.selected_head
                || control.selected_at_ms != record.selected_at_ms
                || record.plan.message_id == receipt.export_plan.message_id
            {
                return Err(AuthorityError::CorruptHistory);
            }
            match &control.outcome {
                OfflineAdmissionControlOutcome::NoAdmission => {
                    let original_intent_digest = original.request().intent.intent_digest()?;
                    if ledger.operations.contains_key(&original.request().operation_id)
                        || ledger.operations.values().any(|(mutation,_,_)| {
                            matches!(mutation, AuthorityMutation::ReserveOfflineAuthorization(body)
                                if body.request.intent.intent_id == original.request().intent.intent_id
                                    || body.request.intent.terms.authorization_id == original.request().intent.terms.authorization_id
                                    || body.request.intent.intent_digest().map(|digest| digest == original_intent_digest).unwrap_or(true))
                        }) {
                        return Err(AuthorityError::CorruptHistory);
                    }
                }
                OfflineAdmissionControlOutcome::ExposureRetained { admission_digest } => {
                    let Some((
                        AuthorityMutation::ReserveOfflineAuthorization(body),
                        peer,
                        MutationResult::OfflineReserved(admission),
                    )) = ledger.operations.get(&original.request().operation_id)
                    else {
                        return Err(AuthorityError::CorruptHistory);
                    };
                    if body.request != *original.request()
                        || admission.request != *original.request()
                        || peer != &original.original.writer_certificate_digest
                        || *admission_digest
                            != digest(
                                "wholepact:offline-committed-admission:v1",
                                admission.as_ref(),
                            )?
                        || admission.reserved_at_ms > record.selected_at_ms
                    {
                        return Err(AuthorityError::CorruptHistory);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Historical selected-outcome evidence, accepted only by exact-ciphertext
/// recovery adapters. It cannot prepare/seal/enqueue an export capability.
pub struct HistoricalOfflineAdmissionExport {
    descriptor: OfflineAuthorizationAdmission,
    plan: OfflineAdmissionExportPlan,
}
impl HistoricalOfflineAdmissionExport {
    pub fn descriptor(&self) -> &OfflineAuthorizationAdmission {
        &self.descriptor
    }
    pub fn export_plan(&self) -> &OfflineAdmissionExportPlan {
        &self.plan
    }
    pub fn authorization_allowed(&self) -> bool {
        false
    }
}
pub struct HistoricalOfflineControlExport {
    descriptor: OfflineAdmissionControl,
    plan: OfflineAdmissionExportPlan,
}
impl HistoricalOfflineControlExport {
    pub fn descriptor(&self) -> &OfflineAdmissionControl {
        &self.descriptor
    }
    pub fn export_plan(&self) -> &OfflineAdmissionExportPlan {
        &self.plan
    }
    pub fn authorization_allowed(&self) -> bool {
        false
    }
}
impl OfflineOriginalBridge<'_> {
    pub fn recover_admission_export_history(
        &self,
        operation: &str,
    ) -> Result<Option<HistoricalOfflineAdmissionExport>> {
        let Some(record) = recover_selected_history(self.journal, self.peer, operation)? else {
            return Ok(None);
        };
        let OutcomeArtifact::Admission(descriptor) = record.artifact else {
            return Err(AuthorityError::Conflict);
        };
        Ok(Some(HistoricalOfflineAdmissionExport {
            descriptor,
            plan: record.plan,
        }))
    }
    pub fn recover_control_export_history(
        &self,
        operation: &str,
    ) -> Result<Option<HistoricalOfflineControlExport>> {
        let Some(record) = recover_selected_history(self.journal, self.peer, operation)? else {
            return Ok(None);
        };
        let OutcomeArtifact::Control(descriptor) = record.artifact else {
            return Err(AuthorityError::Conflict);
        };
        Ok(Some(HistoricalOfflineControlExport {
            descriptor,
            plan: record.plan,
        }))
    }
}
fn recover_selected_history(
    journal: &AuthorityJournal,
    peer: &str,
    operation: &str,
) -> Result<Option<OutcomeRecord>> {
    journal.require_born_read_current()?;
    id(operation)?;
    let c = journal
        .connection
        .lock()
        .map_err(|_| AuthorityError::Storage)?;
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
    crate::journal::authenticate_admission(&tx, peer)?;
    let ledger = crate::journal::load(&tx)?;
    ledger.authenticate_read(
        peer,
        &ledger.policy.account_id,
        &ledger.policy.network_profile_id,
    )?;
    if ledger.snapshot.writer_status == WriterStatus::Quarantined {
        return Err(AuthorityError::RecoveryRequired);
    }
    let Some(original) = offline_retry::read_original(&tx, operation)? else {
        return Ok(None);
    };
    let t = &original.request().intent.terms;
    ledger.authenticate_read(peer, &t.account_id, &t.network_profile_id)?;
    if ledger.snapshot.writer_status == WriterStatus::Quarantined {
        return Err(AuthorityError::RecoveryRequired);
    }
    let policy = ledger
        .offline_policies
        .get(&t.offline_policy_digest)
        .ok_or(AuthorityError::CorruptHistory)?;
    offline_retry::verify_retained(&original, policy)?;
    verify_retained_outcome(&tx, &ledger, &original)?;
    read_outcome(&tx, &original.prepared_record_digest()?)
}

/// Mandatory for EVERY private offline reservation entry, including legacy
/// descriptor-only routes, before replay/apply in the same immediate transaction.
/// A changed operation/head cannot remint a terminally closed original intent.
pub(crate) fn ensure_offline_request_not_terminated(
    c: &Connection,
    request: &ReserveOfflineAuthorization,
) -> Result<()> {
    request.validate()?;
    let mut query = c.prepare("SELECT prepared_digest FROM authority_offline_originals WHERE operation_id=?1 OR intent_id=?2 OR intent_digest=?3 OR authorization_id=?4")?;
    let mut rows = query.query(params![
        request.operation_id,
        request.intent.intent_id,
        request.intent.intent_digest()?,
        request.intent.terms.authorization_id
    ])?;
    while let Some(row) = rows.next()? {
        let prepared: String = row.get(0)?;
        if let Some(record) = read_outcome(c, &prepared)? {
            if matches!(
                record.artifact,
                OutcomeArtifact::Control(OfflineAdmissionControl {
                    outcome: OfflineAdmissionControlOutcome::NoAdmission,
                    ..
                })
            ) {
                return Err(AuthorityError::Conflict);
            }
        }
    }
    Ok(())
}
