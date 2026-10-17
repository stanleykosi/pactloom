//! Historical local cells only. This accepts an already-open read snapshot and
//! creates no current witness, native permission, signing or settlement authority.
use super::super::*;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use wholepact_authority::{
    AutomaticKeyUseAdmission, WitnessDisclosureDescriptor, WriterSessionReceipt,
};

const DISPLAY_LIMIT: usize = 2 * 1024 * 1024;
fn invalid(_: impl std::fmt::Display) -> JournalError {
    JournalError::InvalidBinding
}
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(JournalError::InvalidBinding)
    }
}
fn strings(c: &Connection, sql: &str) -> Result<Vec<String>> {
    let mut q = c.prepare(sql)?;
    let rows = q
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(rows)
}
struct Display {
    rows: Vec<Value>,
    bytes: usize,
}
impl Display {
    fn push(&mut self, table: &str, metadata: Value) -> Result<()> {
        let row = json!({"table": table, "historical_metadata": metadata});
        self.bytes = self
            .bytes
            .checked_add(serde_json::to_vec(&row).map_err(invalid)?.len())
            .filter(|n| *n <= DISPLAY_LIMIT - 1024)
            .ok_or(JournalError::Limit)?;
        self.rows.push(row);
        Ok(())
    }
}

pub(super) fn validate(
    c: &Connection,
    account: &SignerAccountState,
    limits: (u64, u64),
) -> Result<Value> {
    storage::bounded(c, limits)?;
    let mut foreign_keys = c.prepare("PRAGMA foreign_key_check")?;
    require(foreign_keys.query([])?.next()?.is_none())?;
    drop(foreign_keys);
    let mut display = Display {
        rows: Vec::new(),
        bytes: 0,
    };
    enrollments(c, account, &mut display)?;
    bridge(c, account, &mut display)?;
    writers(c, account, &mut display)?;
    sponsors(c, account, &mut display)?;
    automation(c, account, &mut display)?;
    deliveries(c, &mut display)?;
    recovery_generations(c, account, &mut display)?;
    display.push(
        "signer_named_recipient_complete_history",
        serde_json::to_value(named_recipient_inventory::read_all(c, &account.account_id)?)
            .map_err(invalid)?,
    )?;
    settlement_sources(c, account, &mut display)?;
    display.push(
        "signer_settlement_history",
        settlement::read_permanent_stop_history(c, account)?,
    )?;
    let value = json!({
        "purpose": "typed_retained_local_history_only",
        "records": display.rows,
        "remote_exposure": "UNKNOWN without independent complete authenticated witness replay",
        "notice": "Historical expiry, pause and revocation are preserved. No current authority, account emptiness, exposure clearing or fresh settlement is inferred. Signed artifacts, signatures and outbox bytes are never displayed."
    });
    if serde_json::to_vec(&value).map_err(invalid)?.len() > DISPLAY_LIMIT {
        return Err(JournalError::Limit);
    }
    Ok(value)
}

fn enrollments(c: &Connection, account: &SignerAccountState, out: &mut Display) -> Result<()> {
    let mut q=c.prepare("SELECT reference,account_id,agreement_id,participant_id FROM signer_enrollments ORDER BY reference")?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })? {
        let (reference, id, agreement, participant) = row?;
        let e = storage::read_enrollment(c, &reference)?.ok_or(JournalError::NotFound)?;
        require(
            e.account_id() == account.account_id
                && e.account_id() == id
                && e.agreement_id() == agreement
                && e.participant_id() == participant
                && e.receipt().writer_epoch() <= account.writer_epoch,
        )?;
        out.push("signer_enrollments", json!(e))?;
    }
    let mut q=c.prepare("SELECT reference,enrollment_ref,proposal_id,proposal_digest FROM signer_accepted_manifests ORDER BY reference")?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })? {
        let (reference, enrollment, proposal_id, proposal_digest) = row?;
        let m = storage::read_manifest(c, &reference)?.ok_or(JournalError::NotFound)?;
        let e = storage::read_enrollment(c, &enrollment)?.ok_or(JournalError::NotFound)?;
        let p = m.proposal()?;
        require(
            m.enrollment_ref() == enrollment
                && m.terms.account_id == account.account_id
                && m.terms.account_id == e.account_id()
                && m.terms.principal_id == e.principal_id()
                && p.input().proposal_id == proposal_id
                && p.proposal_digest() == proposal_digest
                && p.manifest().agreement.agreement_id == e.agreement_id()
                && p.manifest().agreement.network_profile_id == e.terms.network_profile_id
                && storage::same_native_origin(e.receipt(), m.receipt()),
        )?;
        e.transport().validate_scope(
            e.account_id(),
            e.agreement_id(),
            e.participant_id(),
            Some(p.manifest_digest()),
        )?;
        require(p.manifest().participants.iter().any(|owner| {
            owner.account_id == e.account_id() && owner.participant_id == e.participant_id()
        }))?;
        out.push("signer_accepted_manifests", json!(m))?;
    }
    Ok(())
}

fn bridge(c: &Connection, account: &SignerAccountState, out: &mut Display) -> Result<()> {
    for id in strings(
        c,
        "SELECT authorization_id FROM signer_bridge_requests ORDER BY authorization_id",
    )? {
        let original = storage::read_original(c, &id)?.ok_or(JournalError::NotFound)?;
        require(original.enrollment().account_id() == account.account_id)?;
        let request = bridge_storage::read_request(c, &id)
            .map_err(invalid)?
            .ok_or(JournalError::NotFound)?;
        request.validate_original(&original).map_err(invalid)?;
        out.push("signer_bridge_requests",json!({"reservation":request.reservation,"delivery":request.delivery,"disclosure":request.disclosure}))?;
    }
    for id in strings(
        c,
        "SELECT authorization_id FROM signer_bridge_permits ORDER BY authorization_id",
    )? {
        let request = bridge_storage::read_request(c, &id)
            .map_err(invalid)?
            .ok_or(JournalError::NotFound)?;
        let permit = bridge_storage::read_permit(c, &id)
            .map_err(invalid)?
            .ok_or(JournalError::NotFound)?;
        permit
            .descriptor()
            .matches_request(&request.reservation)
            .map_err(invalid)?;
        hash(permit.witness_certificate_digest())?;
        if let Some(disclosure) = &request.disclosure {
            require(
                permit.witness_certificate_digest()
                    == disclosure.descriptor.pinned_server_certificate_digest
                    && permit.descriptor().witness_id == disclosure.descriptor.witness_id
                    && permit.descriptor().policy_digest == disclosure.descriptor.policy_digest,
            )?;
        }
        out.push("signer_bridge_permits", json!(permit))?;
    }
    for id in strings(
        c,
        "SELECT authorization_id FROM signer_bridge_keyuse ORDER BY authorization_id",
    )? {
        let original = storage::read_original(c, &id)?.ok_or(JournalError::NotFound)?;
        let present: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM signer_automation_keyuse WHERE authorization_id=?1)",
            [&id],
            |r| r.get(0),
        )?;
        require(present == original.original_consent().terms().automation.is_some())?;
        out.push("signer_bridge_keyuse",json!({"authorization_id":id,"signature_outcome":"retained result or UNKNOWN; never safe to repeat"}))?;
    }
    for id in strings(
        c,
        "SELECT authorization_id FROM signer_bridge_results ORDER BY authorization_id",
    )? {
        let original = storage::read_original(c, &id)?.ok_or(JournalError::NotFound)?;
        let result = bridge_storage::read_validated_result(c, &id, &original).map_err(invalid)?;
        out.push("signer_bridge_results",json!({"authorization_id":id,"original_consent_ref":result.original_consent_ref,
            "request_digest":result.request_digest,"result_digest":result.result_digest(),"outbox_digest":result.outbox_digest()}))?;
    }
    Ok(())
}

fn writers(c: &Connection, account: &SignerAccountState, out: &mut Display) -> Result<()> {
    let mut q=c.prepare("SELECT review_digest,disclosure,head_sequence,head_digest,writer_epoch,payload FROM signer_writer_reconciliations ORDER BY head_sequence,review_digest")?;
    let mut prior: Option<(WitnessDisclosureDescriptor, u64, String, u64)> = None;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, u64>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, u64>(4)?,
            r.get::<_, String>(5)?,
        ))
    })? {
        let (review, raw, sequence, head, epoch, payload) = row?;
        let disclosure: WitnessDisclosureDescriptor = decode(raw)?;
        let (receipt, native, history_digest): (
            WriterSessionReceipt,
            NativeConsentReceipt,
            String,
        ) = decode(payload)?;
        disclosure.validate().map_err(invalid)?;
        native.validate()?;
        for h in [
            &review,
            &head,
            &history_digest,
            &receipt.writer_certificate_digest,
            &receipt.reconciled_history_digest,
            &receipt.reconciled_head.digest,
            &receipt.acquired_head.digest,
        ] {
            hash(h)?;
        }
        id(&receipt.session_id)?;
        require(
            disclosure.account_id == account.account_id
                && receipt.disclosure == disclosure
                && epoch > 0
                && epoch <= account.writer_epoch
                && receipt.writer_epoch == epoch
                && native.writer_epoch() <= epoch
                && sequence <= i64::MAX as u64
                && receipt.reconciled_head.sequence.checked_add(1)
                    == Some(receipt.acquired_head.sequence)
                && receipt.acquired_head.sequence <= sequence
                && (receipt.acquired_head.sequence != sequence
                    || receipt.acquired_head.digest == head)
                && receipt.acquired_at_ms < receipt.expires_at_ms
                && receipt.expires_at_ms <= i64::MAX as u64,
        )?;
        if let Some((old, old_sequence, old_head, old_epoch)) = &prior {
            require(
                old == &disclosure
                    && *old_epoch <= epoch
                    && (*old_sequence != sequence || old_head == &head),
            )?;
        }
        prior = Some((disclosure.clone(), sequence, head.clone(), epoch));
        out.push("signer_writer_reconciliations",json!({"review_digest":review,"disclosure":disclosure,"head_sequence":sequence,"head_digest":head,"writer_epoch":epoch,"writer_receipt":receipt,"native_receipt":native,"history_digest":history_digest,
            "unverified_without_witness":"original review preimage and remote head membership"}))?;
    }
    Ok(())
}

fn sponsors(c: &Connection, account: &SignerAccountState, out: &mut Display) -> Result<()> {
    let mut policies: BTreeMap<(String, u64), NativeSponsorPolicyRecord> = BTreeMap::new();
    let mut latest: BTreeMap<String, NativeSponsorPolicyRecord> = BTreeMap::new();
    let mut scope_owners: BTreeMap<String, String> = BTreeMap::new();
    let mut q=c.prepare("SELECT policy_key,version,payload FROM signer_sponsor_policy_events ORDER BY policy_key,version")?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, u64>(1)?,
            r.get::<_, String>(2)?,
        ))
    })? {
        let (key, version, raw) = row?;
        let policy: NativeSponsorPolicyRecord = decode(raw)?;
        policy.validate()?;
        require(
            policy.binding.policy_key == key
                && policy.binding.version == version
                && policy.terms.sponsor.account_id == account.account_id,
        )?;
        // Historical scope remains attached to its original policy key even
        // after pause/revocation or a later scope update, as at insertion.
        for scope in &policy.terms.agreement_scope {
            if let Some(owner) = scope_owners.insert(scope.clone(), key.clone()) {
                require(owner == key)?;
            }
        }
        match latest.get(&key) {
            None => require(version == 1 && policy.status == NativeSponsorPolicyStatus::Active)?,
            Some(old) => require(
                old.binding.version.checked_add(1) == Some(version)
                    && old.status != NativeSponsorPolicyStatus::Revoked
                    && old.principal_id == policy.principal_id
                    && old.witness == policy.witness,
            )?,
        }
        out.push("signer_sponsor_policy_events", json!(policy))?;
        latest.insert(key.clone(), policy.clone());
        policies.insert((key, version), policy);
    }
    for reference in strings(
        c,
        "SELECT manifest_ref FROM signer_sponsor_manifest_bindings ORDER BY manifest_ref",
    )? {
        let binding = sponsor::manifest_binding(c, &reference)?.ok_or(JournalError::NotFound)?;
        let policy = policies
            .get(&(binding.policy_key.clone(), binding.version))
            .ok_or(JournalError::NotFound)?;
        let manifest = storage::read_manifest(c, &reference)?.ok_or(JournalError::NotFound)?;
        require(
            policy.binding == binding
                && policy.status == NativeSponsorPolicyStatus::Active
                && policy.principal_id == manifest.terms.principal_id
                && policy.terms.sponsor.account_id == manifest.terms.account_id,
        )?;
        wholepact_core::sponsor::evaluate_sponsor_policy(
            &policy.terms,
            manifest.proposal()?.manifest(),
        )
        .map_err(invalid)?;
        out.push(
            "signer_sponsor_manifest_bindings",
            json!({"manifest_ref":reference,"binding":binding}),
        )?;
    }
    for reference in strings(
        c,
        "SELECT manifest_ref FROM signer_sponsor_owner_attestations ORDER BY manifest_ref",
    )? {
        let binding = sponsor::manifest_binding(c, &reference)?.ok_or(JournalError::NotFound)?;
        let policy = policies
            .get(&(binding.policy_key.clone(), binding.version))
            .ok_or(JournalError::NotFound)?;
        let manifest = storage::read_manifest(c, &reference)?.ok_or(JournalError::NotFound)?;
        let record = sponsor::read_attestation(c, &reference)?.ok_or(JournalError::NotFound)?;
        sponsor::validate_attestation(&record, &manifest, &binding)?;
        let enrollment = storage::read_enrollment(c, manifest.enrollment_ref())?
            .ok_or(JournalError::NotFound)?;
        require(&record.source == enrollment.transport())?;
        require(
            matches!(&policy.terms.assurance,wholepact_core::MatchAssurance::Attested{verifier_identity} if verifier_identity==&record.verifier_label),
        )?;
        out.push("signer_sponsor_owner_attestations",json!({"manifest_ref":reference,"record":record,"digest":sponsor::attestation_digest(&record)?}))?;
    }
    for id in strings(
        c,
        "SELECT authorization_id FROM signer_original_consents ORDER BY authorization_id",
    )? {
        let original = storage::read_original(c, &id)?.ok_or(JournalError::NotFound)?;
        let t = original.original_consent().terms();
        let binding = sponsor::manifest_binding(c, &t.accepted_manifest_ref)?;
        require(t.sponsor_policy == binding)?;
        match binding {
            Some(binding) => {
                let policy = policies
                    .get(&(binding.policy_key.clone(), binding.version))
                    .ok_or(JournalError::NotFound)?;
                let attestation = sponsor::read_attestation(c, &t.accepted_manifest_ref)?
                    .ok_or(JournalError::NotFound)?;
                require(
                    policy.principal_id == t.principal_id
                        && policy.status == NativeSponsorPolicyStatus::Active
                        && attestation.source == t.transport
                        && t.sponsor_owner_attestation_digest.as_deref()
                            == Some(sponsor::attestation_digest(&attestation)?.as_str()),
                )?;
            }
            None => require(t.sponsor_owner_attestation_digest.is_none())?,
        }
    }
    Ok(())
}

fn automation(c: &Connection, account: &SignerAccountState, out: &mut Display) -> Result<()> {
    let mut all: BTreeMap<(String, u64), NativeAutomationGrantRecord> = BTreeMap::new();
    let mut latest: BTreeMap<String, NativeAutomationGrantRecord> = BTreeMap::new();
    let mut q=c.prepare("SELECT grant_id,revision,enrollment_ref,payload FROM signer_automation_grant_events ORDER BY grant_id,revision")?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, u64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })? {
        let (id, revision, enrollment, raw) = row?;
        let grant: NativeAutomationGrantRecord = decode(raw)?;
        automation::validate_transition(latest.get(&id), &grant)?;
        automation::validate_account_policy(c, &grant.policy)?;
        let e = storage::read_enrollment(c, &enrollment)?.ok_or(JournalError::NotFound)?;
        let application = match e.transport() {
            TransportIdentityBinding::LocalProcess {
                transport_identity_id,
                ..
            } => transport_identity_id,
            _ => return Err(JournalError::InvalidBinding),
        };
        require(
            grant.binding.grant_id == id
                && grant.binding.revision == revision
                && grant.enrollment_ref == enrollment
                && grant.terms.account_id == account.account_id
                && e.account_id() == account.account_id
                && grant.principal_id == e.principal_id()
                && grant.terms.writer_epoch == e.receipt().writer_epoch()
                && grant.terms.writer_epoch <= account.writer_epoch
                && grant.terms.application_id == *application
                && grant.terms.agreement_ids == [e.agreement_id().to_string()]
                && grant.terms.network_profile == e.terms.network_profile_id
                && grant.policy.maximum_outstanding_debit.as_zatoshis()
                    <= e.budget_limit_zatoshis()
                && (grant.status != AutomationGrantStatus::Active
                    || storage::same_native_origin(&grant.receipt, e.receipt())),
        )?;
        out.push("signer_automation_grant_events", json!(grant))?;
        latest.insert(id.clone(), grant.clone());
        all.insert((id, revision), grant);
    }
    let mut q = c.prepare(
        "SELECT authorization_id,payload FROM signer_automation_keyuse ORDER BY authorization_id",
    )?;
    for row in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (id, raw) = row?;
        let a: AutomaticKeyUseAdmission = decode(raw)?;
        a.matches_request(&a.request).map_err(invalid)?;
        let original = storage::read_original(c, &id)?.ok_or(JournalError::NotFound)?;
        let t = original.original_consent().terms();
        let binding = t.automation.as_ref().ok_or(JournalError::InvalidBinding)?;
        let grant = all
            .get(&(binding.grant.grant_id.clone(), binding.grant.revision))
            .ok_or(JournalError::NotFound)?;
        let permit = bridge_storage::read_permit(c, &id)
            .map_err(invalid)?
            .ok_or(JournalError::NotFound)?;
        require(
            a.reservation.request.authorization_id == id
                && a.request.automation == binding.grant
                && grant.binding == binding.grant
                && a.reservation == *permit.descriptor()
                && a.witness_id == grant.witness.witness_id
                && a.policy_digest == grant.witness.policy_digest
                && grant.enrollment_ref == t.enrollment_ref,
        )?;
        out.push("signer_automation_keyuse", json!(a))?;
    }
    // An original automation consent can precede key use; still validate its
    // immutable original grant even when no admission/result was ever produced.
    for id in strings(
        c,
        "SELECT authorization_id FROM signer_original_consents ORDER BY authorization_id",
    )? {
        let o = storage::read_original(c, &id)?.ok_or(JournalError::NotFound)?;
        let t = o.original_consent().terms();
        if let Some(b) = &t.automation {
            let grant = all
                .get(&(b.grant.grant_id.clone(), b.grant.revision))
                .ok_or(JournalError::NotFound)?;
            require(
                grant.binding == b.grant
                    && grant.status == AutomationGrantStatus::Active
                    && grant.enrollment_ref == t.enrollment_ref
                    && grant.principal_id == t.principal_id
                    && grant.terms.account_id == t.account_id
                    && grant.terms.writer_epoch == t.receipt.writer_epoch()
                    && b.authorization_expires_at_ms <= grant.terms.expires_at_ms,
            )?;
        }
    }
    Ok(())
}

fn deliveries(c: &Connection, out: &mut Display) -> Result<()> {
    let mut q=c.prepare("SELECT operation_id,reference,authorization_id,payload FROM signer_result_redeliveries ORDER BY operation_id")?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })? {
        let (operation, reference, id, raw) = row?;
        let record: ResultRedeliveryRecord = decode(raw)?;
        let original = storage::read_original(c, &id)?.ok_or(JournalError::NotFound)?;
        let result = bridge_storage::read_validated_result(c, &id, &original).map_err(invalid)?;
        record.validate_original(&original, &result)?;
        require(
            record.reference() == reference
                && record.terms().request.operation_id == operation
                && record.terms().request.authorization_id == id,
        )?;
        out.push("signer_result_redeliveries", json!(record))?;
    }
    let mut q=c.prepare("SELECT operation_id,authorization_id,payload FROM signer_dispatch_requests ORDER BY operation_id")?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })? {
        let (operation, id, raw) = row?;
        let record: RetainedDispatch = decode(raw)?;
        let original = storage::read_original(c, &id)?.ok_or(JournalError::NotFound)?;
        bridge_storage::read_validated_result(c, &id, &original).map_err(invalid)?;
        record.validate(&original).map_err(invalid)?;
        let request = bridge_storage::read_request(c, &id)
            .map_err(invalid)?
            .ok_or(JournalError::NotFound)?;
        require(
            record.exact.operation_id == operation
                && record.request.history.authorization_id == id
                && record.exact.reservation_request_digest
                    == request.reservation.request_digest().map_err(invalid)?
                && request
                    .disclosure
                    .as_ref()
                    .is_some_and(|d| d.descriptor == record.witness),
        )?;
        out.push("signer_dispatch_requests", json!(record))?;
    }
    Ok(())
}

fn settlement_sources(
    c: &Connection,
    account: &SignerAccountState,
    out: &mut Display,
) -> Result<()> {
    let mut q = c.prepare(
        "SELECT reference,account_id,payload FROM signer_settlement_sources ORDER BY reference",
    )?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })? {
        let (reference, row_account, raw) = row?;
        let source: SignerSettlementSource = decode(raw)?;
        source.validate_history(account)?;
        require(source.reference() == reference && source.account_id() == row_account)?;
        out.push("signer_settlement_sources", json!({"source":source,
            "authority":"retained historical enrollment only; no current source authentication or canonical observation"}))?;
    }
    Ok(())
}

fn recovery_generations(
    c: &Connection,
    account: &SignerAccountState,
    out: &mut Display,
) -> Result<()> {
    let mut records: BTreeMap<String, (RecoveryActivationRecord, u8)> = BTreeMap::new();
    let mut q = c.prepare("SELECT generation_id,phase,operation_id,inventory_digest,fence_digest,writer_epoch,payload FROM signer_recovery_generations ORDER BY generation_id,phase")?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, u64>(5)?,
            r.get::<_, String>(6)?,
        ))
    })? {
        let (generation, phase, operation, inventory, fence, epoch, raw) = row?;
        let record: RecoveryActivationRecord = decode(raw)?;
        id(&record.operation_id)?;
        for h in [
            &record.generation_id,
            &record.inventory_digest,
            &record.fence_digest,
            &record.history_digest,
            &record.source_bundle_digest,
            &record.source_component_digest,
            &record.review_digest,
        ] {
            hash(h)?;
        }
        if let Some(h) = &record.account_use_retention_digest {
            hash(h)?;
        }
        require(
            record.generation_id == generation
                && record.operation_id == operation
                && record.inventory_digest == inventory
                && record.fence_digest == fence
                && record.writer_epoch == epoch
                && epoch > 0
                && epoch <= account.writer_epoch
                && record.account_id == account.account_id
                && record.target_profile.is_absolute()
                && record.target_profile.parent().is_some(),
        )?;
        let bit = match phase.as_str() {
            "prepared" => 1,
            "committed" => 2,
            _ => return Err(JournalError::InvalidBinding),
        };
        match records.get_mut(&generation) {
            Some((old, phases)) => {
                require(*old == record && *phases & bit == 0)?;
                *phases |= bit;
            }
            None => {
                records.insert(generation, (record.clone(), bit));
            }
        }
        out.push("signer_recovery_generations", json!({"phase":phase,"record":record,
            "authority":"historical paired record only; original source, fence and filesystem state are not freshly authenticated"}))?;
    }
    // Successor creation records both phases atomically. Incomplete pairs are
    // malformed retained cells, never evidence that activation may be retried.
    for (_, phases) in records.values() {
        require(*phases == 3)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wholepact_authority::AuthorityHead;

    fn account() -> SignerAccountState {
        SignerAccountState {
            account_id: "historical-account".into(),
            writer_epoch: 2,
            recovery_required: true,
        }
    }
    fn connection() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(SCHEMA).unwrap();
        c.execute(
            "INSERT INTO signer_account VALUES(1,?1,2,1)",
            [&account().account_id],
        )
        .unwrap();
        c
    }
    fn retained(c: &Connection, account_id: &str, head: &str) {
        let d = WitnessDisclosureDescriptor {
            endpoint: "127.0.0.1:443".into(),
            server_name: "witness.example".into(),
            witness_id: "historical-witness".into(),
            account_id: account_id.into(),
            network_profile_id: "historical-network".into(),
            policy_digest: "ab".repeat(32),
            pinned_server_certificate_digest: "cd".repeat(32),
        };
        let receipt = WriterSessionReceipt {
            session_id: "historical-session".into(),
            writer_certificate_digest: "ef".repeat(32),
            writer_epoch: 1,
            reconciled_head: AuthorityHead {
                sequence: 1,
                digest: "12".repeat(32),
            },
            reconciled_history_digest: "34".repeat(32),
            acquired_head: AuthorityHead {
                sequence: 2,
                digest: "56".repeat(32),
            },
            acquired_at_ms: 10,
            expires_at_ms: 20,
            disclosure: d.clone(),
        };
        let native = NativeConsentReceipt {
            native_session_id: "78".repeat(32),
            trusted_launch_measurement: "9a".repeat(32),
            permission_generation: 1,
            writer_epoch: 1,
            nonce: "bc".repeat(32),
            reviewed_at_ms: 1,
            expires_at_ms: 2,
        };
        c.execute(
            "INSERT INTO signer_writer_reconciliations VALUES(?1,?2,3,?3,1,?4)",
            rusqlite::params![
                "de".repeat(32),
                serde_json::to_string(&d).unwrap(),
                head,
                serde_json::to_string(&(receipt, native, "f0".repeat(32))).unwrap()
            ],
        )
        .unwrap();
    }
    fn display() -> Display {
        Display {
            rows: vec![],
            bytes: 0,
        }
    }

    #[test]
    fn historical_expiry_and_quarantine_do_not_drop_nonempty_writer_cells() {
        let mut c = connection();
        retained(&c, &account().account_id, &"11".repeat(32));
        let before: u64 = c
            .query_row("SELECT total_changes()", [], |r| r.get(0))
            .unwrap();
        // The same reader accepts an existing archive read transaction.
        let tx = c.transaction().unwrap();
        let mut out = display();
        writers(&tx, &account(), &mut out).unwrap();
        assert_eq!(out.rows.len(), 1);
        assert_eq!(
            out.rows[0]["historical_metadata"]["writer_receipt"]["expires_at_ms"],
            20
        );
        let after: u64 = tx
            .query_row("SELECT total_changes()", [], |r| r.get(0))
            .unwrap();
        assert_eq!(after, before);
        assert!(account().recovery_required);
    }

    #[test]
    fn rejects_writer_account_substitution() {
        let c = connection();
        retained(&c, "another-account", &"11".repeat(32));
        assert!(writers(&c, &account(), &mut display()).is_err());
    }

    #[test]
    fn rejects_conflicting_retained_heads_at_same_sequence() {
        let c = connection();
        retained(&c, &account().account_id, &"11".repeat(32));
        c.execute("INSERT INTO signer_writer_reconciliations SELECT ?1,disclosure,head_sequence,?2,writer_epoch,payload FROM signer_writer_reconciliations LIMIT 1", rusqlite::params!["22".repeat(32), "33".repeat(32)]).unwrap();
        assert!(writers(&c, &account(), &mut display()).is_err());
    }

    #[test]
    fn rejects_orphan_cells_even_if_foreign_key_enforcement_was_disabled() {
        let c = connection();
        c.execute_batch("PRAGMA foreign_keys=OFF; INSERT INTO signer_bridge_keyuse VALUES('orphan-authorization');").unwrap();
        assert!(matches!(
            validate(&c, &account(), (100_000, 64 * 1024 * 1024)),
            Err(JournalError::InvalidBinding)
        ));
    }

    #[test]
    fn inert_display_has_an_independent_bounded_budget() {
        let mut out = display();
        assert!(matches!(
            out.push("synthetic", json!("x".repeat(DISPLAY_LIMIT))),
            Err(JournalError::Limit)
        ));
        assert!(out.rows.is_empty());
    }
    fn generation(c: &Connection, both: bool) {
        let r = RecoveryActivationRecord {
            account_use_retention_digest: Some("11".repeat(32)),
            operation_id: "historical-recovery".into(),
            generation_id: "22".repeat(32),
            inventory_digest: "33".repeat(32),
            fence_digest: "44".repeat(32),
            history_digest: "55".repeat(32),
            account_id: account().account_id,
            writer_epoch: 2,
            source_bundle_digest: "66".repeat(32),
            source_component_digest: "77".repeat(32),
            target_profile: std::path::PathBuf::from("/historical/never-opened-profile"),
            review_digest: "88".repeat(32),
        };
        for phase in if both {
            vec!["prepared", "committed"]
        } else {
            vec!["prepared"]
        } {
            c.execute(
                "INSERT INTO signer_recovery_generations VALUES(?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params![
                    r.generation_id,
                    phase,
                    r.operation_id,
                    r.inventory_digest,
                    r.fence_digest,
                    r.writer_epoch,
                    serde_json::to_string(&r).unwrap()
                ],
            )
            .unwrap();
        }
    }
    #[test]
    fn retains_paired_historical_generations_without_reopening_paths() {
        let c = connection();
        generation(&c, true);
        let mut out = display();
        recovery_generations(&c, &account(), &mut out).unwrap();
        assert_eq!(out.rows.len(), 2);
        assert_eq!(
            out.rows[0]["historical_metadata"]["record"]["target_profile"],
            "/historical/never-opened-profile"
        );
    }
    #[test]
    fn rejects_malformed_unreferenced_settlement_source() {
        let c = connection();
        c.execute(
            "INSERT INTO signer_settlement_sources VALUES(?1,?2,?3)",
            rusqlite::params!["ab".repeat(32), account().account_id, "{}"],
        )
        .unwrap();
        let before = c.total_changes();
        assert!(settlement_sources(&c, &account(), &mut display()).is_err());
        assert_eq!(before, c.total_changes());
    }
    #[test]
    fn rejects_incomplete_historical_generation_pairs() {
        let c = connection();
        generation(&c, false);
        assert!(recovery_generations(&c, &account(), &mut display()).is_err());
    }
}
