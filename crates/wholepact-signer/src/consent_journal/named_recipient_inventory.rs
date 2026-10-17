//! Complete historical named-recipient inventory, never an authority factory.
//! Only nonsecret typed commitments/references leave this reader. Exact private
//! profile/original/result payloads and encrypted envelopes remain in the DB.
use super::named_recipient_records::*;
use super::*;
use rusqlite::Connection;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct NamedRecipientProfileFingerprintV1 {
    pub(crate) reference: String,
    pub(crate) enrollment_ref: String,
    pub(crate) manifest_ref: String,
    pub(crate) full_viewing_key_digest: String,
    pub(crate) original_setup_digest: String,
    pub(crate) native_review_digest: String,
    pub(crate) native_origin_digest: String,
    pub(crate) verifier_signing_key_digest: String,
    pub(crate) verifier_transport_key_digest: String,
    pub(crate) witness_transport_key_digest: String,
    pub(crate) witness_certificate_digest: String,
    pub(crate) return_transport_key_digest: String,
    pub(crate) transport_key_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct NamedRecipientOriginalFingerprintV1 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) born_origin_digest: Option<String>,
    pub(crate) reference: String,
    pub(crate) profile_ref: String,
    pub(crate) authorization_id: String,
    pub(crate) terms_digest: String,
    pub(crate) original_artifact_digest: String,
    pub(crate) canonical_artifact_digest: String,
    pub(crate) transformation_digest: String,
    pub(crate) named_assertion_digest: String,
    pub(crate) original_request_digest: String,
    pub(crate) assertion_package_digest: String,
    pub(crate) validity_not_before_ms: u64,
    pub(crate) validity_expires_ms: u64,
    pub(crate) reservation_request_digest: String,
    pub(crate) admission_export_template_digest: String,
    pub(crate) own_policy_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct NamedIntentOutboxFingerprintV1 {
    pub(crate) authorization_id: String,
    pub(crate) original_ref: String,
    pub(crate) profile_ref: String,
    pub(crate) stream: String,
    pub(crate) sequence: u64,
    pub(crate) message_id: String,
    pub(crate) content_hash: String,
    pub(crate) payload_digest: String,
    pub(crate) envelope_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct NamedRecipientReceiptFingerprintV1 {
    pub(crate) profile_ref: String,
    pub(crate) stream: String,
    pub(crate) sequence: u64,
    pub(crate) message_id: String,
    pub(crate) content_hash: String,
    pub(crate) payload_digest: String,
    pub(crate) envelope_digest: String,
    pub(crate) immutable_slot: Option<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct NamedRecipientStartedFingerprintV1 {
    pub(crate) authorization_id: String,
    pub(crate) original_ref: String,
    pub(crate) marker_digest: String,
}
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct NamedRecipientResultFingerprintV1 {
    pub(crate) authorization_id: String,
    pub(crate) original_ref: String,
    pub(crate) started_digest: String,
    pub(crate) result_digest: String,
    pub(crate) record_digest: String,
}
/// No Deserialize and no private payloads. Informational only, even when all
/// historical linkage validates. No epoch, expiry or replay position is renewed.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct NamedRecipientHistoryInventoryV1 {
    pub(crate) schema_version: u16,
    pub(crate) profiles: Vec<NamedRecipientProfileFingerprintV1>,
    pub(crate) originals: Vec<NamedRecipientOriginalFingerprintV1>,
    pub(crate) intent_outbox: Vec<NamedIntentOutboxFingerprintV1>,
    pub(crate) receipts: Vec<NamedRecipientReceiptFingerprintV1>,
    pub(crate) started: Vec<NamedRecipientStartedFingerprintV1>,
    pub(crate) results: Vec<NamedRecipientResultFingerprintV1>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) born_dispatch_requests: Vec<(String, String, String, String)>,
}
impl SignerConsentJournal {
    pub(crate) fn named_recipient_history_inventory(
        &self,
        session: &SignerConsentSession,
    ) -> Result<NamedRecipientHistoryInventoryV1> {
        let account = self.account_state()?;
        let permission = session.read_lease(&self.binding(), &account)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction()?;
        storage::check_account(&tx, &account)?;
        storage::bounded(&tx, self.capacity_limits())?;
        let inventory = read_all(&tx, &account.account_id)?;
        permission.check_current()?;
        tx.rollback()?;
        Ok(inventory)
    }
}
/// Legacy consumers cannot silently omit setup/receipt-only history either.
pub(super) fn require_absent(c: &Connection) -> Result<()> {
    let present: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM signer_named_recipient_profiles UNION ALL SELECT 1 FROM signer_named_recipient_originals UNION ALL SELECT 1 FROM signer_named_recipient_receipts UNION ALL SELECT 1 FROM signer_named_recipient_started UNION ALL SELECT 1 FROM signer_named_recipient_results UNION ALL SELECT 1 FROM signer_named_intent_outbox UNION ALL SELECT 1 FROM signer_named_recipient_dispatch_requests)",
        [], |r| r.get(0))?;
    if present {
        return Err(JournalError::NamedRecipientHistoryUnsupported);
    }
    Ok(())
}
pub(super) fn read_all(c: &Connection, account: &str) -> Result<NamedRecipientHistoryInventoryV1> {
    #[cfg(not(feature = "offline-review-foundation"))]
    require_absent(c)?;
    read_records(c, account, true)
}
/// Raw encrypted archive/schema retention may preserve records without a
/// transport-capable build. This function deliberately returns no typed profile.
pub(super) fn validate_archive_rows(c: &Connection, account: &str) -> Result<()> {
    read_records(c, account, false).map(|_| ())
}
fn read_records(
    c: &Connection,
    account: &str,
    typed: bool,
) -> Result<NamedRecipientHistoryInventoryV1> {
    let mut inventory = NamedRecipientHistoryInventoryV1 {
        schema_version: 1,
        profiles: vec![],
        originals: vec![],
        intent_outbox: vec![],
        receipts: vec![],
        started: vec![],
        results: vec![],
        born_dispatch_requests: vec![],
    };
    let mut profiles = BTreeMap::new();
    let mut q = c.prepare("SELECT reference,original_setup_digest,account_id,enrollment_ref,manifest_ref,payload FROM signer_named_recipient_profiles ORDER BY reference")?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
        ))
    })? {
        let (reference, setup_digest, owner, enrollment_ref, manifest_ref, payload) = row?;
        let profile: NamedRecipientProfileRecordV1 = decode(payload)?;
        if typed {
            profile.validate()?;
        } else {
            profile.validate_structure()?;
            #[cfg(feature = "offline-review-foundation")]
            profile.validate()?;
        }
        let enrollment =
            storage::read_enrollment(c, &enrollment_ref)?.ok_or(JournalError::InvalidBinding)?;
        let manifest =
            storage::read_manifest(c, &manifest_ref)?.ok_or(JournalError::InvalidBinding)?;
        if setup_digest != profile.original_setup_digest
            || reference != profile.reference
            || owner != account
            || profile.account_id != owner
            || enrollment_ref != profile.enrollment_ref
            || manifest_ref != profile.manifest_ref
            || enrollment.account_id() != account
            || enrollment.account_fvk_digest() != profile.full_viewing_key_digest
            || manifest.enrollment_ref() != enrollment_ref
            || manifest.terms.account_id != account
        {
            return Err(JournalError::InvalidBinding);
        }
        if let Some(born) = &profile.born_profile {
            let actual = super::account_use_storage::inspect(c, account)?;
            if actual.genesis() != Some(&born.genesis) {
                return Err(JournalError::InvalidBinding);
            }
            born.validate_local_manifest(&profile, &enrollment, &manifest)?;
        }
        inventory.profiles.push(NamedRecipientProfileFingerprintV1 {
            reference: reference.clone(),
            enrollment_ref,
            manifest_ref,
            full_viewing_key_digest: profile.full_viewing_key_digest.clone(),
            original_setup_digest: profile.original_setup_digest.clone(),
            native_review_digest: profile.native_review_digest.clone(),
            native_origin_digest: profile.native_origin_digest.clone(),
            verifier_signing_key_digest: hex::encode(Sha256::digest(
                profile.verifier_signing_public_key,
            )),
            verifier_transport_key_digest: transport_fingerprint(
                &profile.verifier_transport_public_key,
            ),
            witness_transport_key_digest: transport_fingerprint(
                &profile.witness_transport_public_key,
            ),
            witness_certificate_digest: profile.witness_certificate_digest.clone(),
            return_transport_key_digest: transport_fingerprint(
                &profile.return_transport_public_key,
            ),
            transport_key_digest: transport_fingerprint(&profile.transport_public_key),
        });
        profiles.insert(reference, profile);
    }
    drop(q);
    let mut originals = BTreeMap::new();
    let mut q = c.prepare("SELECT reference,profile_ref,authorization_id,payload FROM signer_named_recipient_originals ORDER BY reference")?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })? {
        let (reference, profile_ref, authorization_id, payload) = row?;
        let original: NamedRecipientOriginalRecordV1 = decode(payload)?;
        let profile = profiles
            .get(&profile_ref)
            .ok_or(JournalError::InvalidBinding)?;
        if typed {
            original.validate(profile)?;
        } else {
            original.validate_structure(profile)?;
            #[cfg(feature = "offline-review-foundation")]
            original.validate(profile)?;
        }
        let manifest = storage::read_manifest(c, &profile.manifest_ref)?
            .ok_or(JournalError::InvalidBinding)?;
        if original.reference != reference
            || original.profile_ref != profile_ref
            || original.terms.authorization_id != authorization_id
            || original.terms.manifest_digest != manifest.manifest_digest()
            || original.terms.proposal_digest != manifest.proposal_digest()
        {
            return Err(JournalError::InvalidBinding);
        }
        validate_manifest_terms(c, profile, &original, &manifest)?;
        if let Some(origin) = &original.born_origin {
            let enrollment = storage::read_enrollment(c, &profile.enrollment_ref)?
                .ok_or(JournalError::InvalidBinding)?;
            origin.require_retained_signer(c, profile, &enrollment)?;
            origin.checkpoint_receipt.require_retained(c)?;
        }
        let alias: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM signer_original_consents WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_offline_original_consents WHERE authorization_id=?1)", [&authorization_id], |r| r.get(0))?;
        if alias {
            return Err(JournalError::Conflict);
        }
        inventory
            .originals
            .push(NamedRecipientOriginalFingerprintV1 {
                born_origin_digest: original
                    .born_origin
                    .as_ref()
                    .map(|o| o.digest())
                    .transpose()?,
                reference,
                profile_ref,
                authorization_id: authorization_id.clone(),
                terms_digest: original
                    .terms
                    .terms_digest()
                    .map_err(|_| JournalError::InvalidBinding)?,
                original_artifact_digest: original.original_artifact_digest.clone(),
                canonical_artifact_digest: original.canonical_artifact_digest.clone(),
                transformation_digest: original.transformation_digest.clone(),
                named_assertion_digest: original.named_assertion_digest.clone(),
                original_request_digest: original.original_request_digest.clone(),
                assertion_package_digest: original.assertion_package_digest.clone(),
                validity_not_before_ms: original.validity_not_before_ms,
                validity_expires_ms: original.validity_expires_ms,
                reservation_request_digest: original.reservation_request_digest.clone(),
                admission_export_template_digest: hex::encode(Sha256::digest(
                    encode(&original.admission_export_template)?.as_bytes(),
                )),
                own_policy_digest: original.own_policy_digest.clone(),
            });
        originals.insert(authorization_id, original);
    }
    drop(q);
    // Every committed original and its immutable ciphertext are one transaction.
    // Missing, orphaned, mixed-original or duplicate rows are never partial success.
    let mut seen_originals = BTreeSet::new();
    let mut outbox_streams = BTreeMap::new();
    let mut outbox_messages = BTreeSet::new();
    let mut outbox_bytes = 0_usize;
    let mut q = c.prepare("SELECT authorization_id,original_ref,profile_ref,stream,sequence,message_id,content_hash,payload_digest,envelope_digest,preview_json,envelope_hex FROM signer_named_intent_outbox ORDER BY profile_ref,stream,sequence")?;
    for row in q.query_map([], |r| {
        Ok(NamedIntentOutboxRecordV1 {
            authorization_id: r.get(0)?,
            original_ref: r.get(1)?,
            profile_ref: r.get(2)?,
            stream: r.get(3)?,
            sequence: r.get(4)?,
            message_id: r.get(5)?,
            content_hash: r.get(6)?,
            payload_digest: r.get(7)?,
            envelope_digest: r.get(8)?,
            preview_json: r.get(9)?,
            envelope_hex: r.get(10)?,
        })
    })? {
        let row = row?;
        let original = originals
            .get(&row.authorization_id)
            .ok_or(JournalError::InvalidBinding)?;
        let profile = profiles
            .get(&row.profile_ref)
            .ok_or(JournalError::InvalidBinding)?;
        if typed {
            row.validate(original, profile)?;
        } else {
            row.validate_structure(original, profile)?;
            #[cfg(feature = "offline-review-foundation")]
            row.validate(original, profile)?;
        }
        let sequence = outbox_streams
            .entry((row.profile_ref.clone(), row.stream.clone()))
            .or_insert(0_u64);
        if !seen_originals.insert(row.authorization_id.clone())
            || !outbox_messages.insert((
                row.profile_ref.clone(),
                row.stream.clone(),
                row.message_id.clone(),
            ))
            || row.sequence != sequence.checked_add(1).ok_or(JournalError::Limit)?
        {
            return Err(JournalError::InvalidBinding);
        }
        *sequence = row.sequence;
        outbox_bytes = outbox_bytes
            .checked_add(row.envelope_hex.len() / 2)
            .ok_or(JournalError::Limit)?;
        if seen_originals.len() > 8192
            || outbox_streams.len() > 512
            || outbox_bytes > 64 * 1024 * 1024
        {
            return Err(JournalError::Limit);
        }
        inventory
            .intent_outbox
            .push(NamedIntentOutboxFingerprintV1 {
                authorization_id: row.authorization_id,
                original_ref: row.original_ref,
                profile_ref: row.profile_ref,
                stream: row.stream,
                sequence: row.sequence,
                message_id: row.message_id,
                content_hash: row.content_hash,
                payload_digest: row.payload_digest,
                envelope_digest: row.envelope_digest,
            });
    }
    if seen_originals.len() != originals.len() {
        return Err(JournalError::InvalidBinding);
    }
    drop(q);
    let mut streams = BTreeMap::new();
    let mut retained_bytes = 0_usize;
    let mut q = c.prepare("SELECT profile_ref,stream,sequence,message_id,content_hash,payload_digest,envelope_digest,immutable_slot,envelope_hex FROM signer_named_recipient_receipts ORDER BY profile_ref,stream,sequence")?;
    for row in q.query_map([], |r| {
        Ok((
            NamedRecipientReceiptFingerprintV1 {
                profile_ref: r.get(0)?,
                stream: r.get(1)?,
                sequence: r.get(2)?,
                message_id: r.get(3)?,
                content_hash: r.get(4)?,
                payload_digest: r.get(5)?,
                envelope_digest: r.get(6)?,
                immutable_slot: r.get(7)?,
            },
            r.get::<_, String>(8)?,
        ))
    })? {
        let (receipt, raw) = row?;
        for h in [
            &receipt.profile_ref,
            &receipt.stream,
            &receipt.message_id,
            &receipt.content_hash,
            &receipt.payload_digest,
            &receipt.envelope_digest,
        ] {
            hash(h)?;
        }
        if let Some(slot) = &receipt.immutable_slot {
            hash(slot)?;
        }
        if !profiles.contains_key(&receipt.profile_ref)
            || raw.len() > 2 * 1_048_576
            || raw.is_empty()
        {
            return Err(JournalError::InvalidBinding);
        }
        let envelope = Zeroizing::new(hex::decode(&raw).map_err(|_| JournalError::InvalidBinding)?);
        if hex::encode(envelope.as_slice()) != raw
            || receipt.envelope_digest
                != domain_digest(b"wholepact.encrypted-envelope.v1\0", envelope.as_slice())
        {
            return Err(JournalError::InvalidBinding);
        }
        let sequence = streams
            .entry((receipt.profile_ref.clone(), receipt.stream.clone()))
            .or_insert(0_u64);
        if receipt.sequence != sequence.checked_add(1).ok_or(JournalError::Limit)? {
            return Err(JournalError::InvalidBinding);
        }
        *sequence = receipt.sequence;
        retained_bytes = retained_bytes
            .checked_add(envelope.len())
            .ok_or(JournalError::Limit)?;
        inventory.receipts.push(receipt);
        if inventory.receipts.len() > 8192
            || streams.len() > 512
            || retained_bytes > 64 * 1024 * 1024
        {
            return Err(JournalError::Limit);
        }
    }
    drop(q);
    let mut started_records = BTreeMap::new();
    let mut return_sequences = BTreeSet::new();
    let mut q = c.prepare("SELECT authorization_id,original_ref,marker_digest,payload FROM signer_named_recipient_started ORDER BY authorization_id")?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })? {
        let (authorization_id, original_ref, marker_digest, payload) = row?;
        let started: NamedRecipientStartedRecordV1 = decode(payload)?;
        let original = originals
            .get(&authorization_id)
            .ok_or(JournalError::InvalidBinding)?;
        started.validate(original)?;
        if let Some(final_review) = &started.final_review {
            let profile = profiles
                .get(&original.profile_ref)
                .ok_or(JournalError::InvalidBinding)?;
            if final_review.witness.pinned_server_certificate_digest
                != profile.witness_certificate_digest
                || final_review.enrollment.witness_transport_key_digest
                    != transport_fingerprint(&profile.witness_transport_public_key)
                || !inventory.receipts.iter().any(|r| {
                    r.profile_ref == original.profile_ref
                        && r.envelope_digest == final_review.assertion_envelope_digest
                })
                || !return_sequences.insert((
                    false,
                    original.terms.network_profile_id.clone(),
                    original.terms.agreement_id.clone(),
                    original.terms.offline_signer_key_digest.clone(),
                    original.terms.return_recipient_key_digest.clone(),
                    final_review.return_sequence,
                ))
            {
                return Err(JournalError::InvalidBinding);
            }
        }
        if let Some(review) = &started.born_final_review {
            let profile = profiles
                .get(&original.profile_ref)
                .ok_or(JournalError::InvalidBinding)?;
            review.validate_profile(profile, original)?;
            review.admission_receipt.require_retained(c)?;
            if review.witness.pinned_server_certificate_digest != profile.witness_certificate_digest
                || !inventory.receipts.iter().any(|r| {
                    r.profile_ref == original.profile_ref
                        && r.envelope_digest == review.assertion_envelope_digest
                })
                || !return_sequences.insert((
                    true,
                    original.terms.network_profile_id.clone(),
                    original.terms.agreement_id.clone(),
                    original.terms.offline_signer_key_digest.clone(),
                    original.terms.return_recipient_key_digest.clone(),
                    review.return_sequence,
                ))
            {
                return Err(JournalError::InvalidBinding);
            }
        }
        if started.authorization_id != authorization_id
            || started.original_ref != original_ref
            || started.marker_digest()? != marker_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        inventory.started.push(NamedRecipientStartedFingerprintV1 {
            authorization_id: authorization_id.clone(),
            original_ref,
            marker_digest,
        });
        started_records.insert(authorization_id, started);
    }
    drop(q);
    let mut q = c.prepare("SELECT authorization_id,result_digest,payload FROM signer_named_recipient_results ORDER BY authorization_id")?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })? {
        let (authorization_id, result_digest, payload) = row?;
        let result: NamedRecipientResultRecordV1 = decode(payload)?;
        result.validate(
            started_records
                .get(&authorization_id)
                .ok_or(JournalError::InvalidBinding)?,
            originals
                .get(&result.authorization_id)
                .ok_or(JournalError::InvalidBinding)?,
        )?;
        if result.authorization_id != authorization_id || result.result_digest != result_digest {
            return Err(JournalError::InvalidBinding);
        }
        let record_digest = digest("wholepact:named-recipient-complete-result:v1", &result)?;
        inventory.results.push(NamedRecipientResultFingerprintV1 {
            record_digest,
            authorization_id,
            original_ref: result.original_ref,
            started_digest: result.started_digest,
            result_digest,
        });
    }
    drop(q);
    let mut q=c.prepare("SELECT operation_id,authorization_id,original_ref,request_digest,payload FROM signer_named_recipient_dispatch_requests ORDER BY operation_id")?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
        ))
    })? {
        let (operation, authorization, reference, commitment, raw) = row?;
        #[cfg(target_os = "linux")]
        {
            let record: RetainedBornDispatchV1 = decode(raw)?;
            let original = originals
                .get(&authorization)
                .ok_or(JournalError::InvalidBinding)?;
            let started = started_records
                .get(&authorization)
                .ok_or(JournalError::InvalidBinding)?;
            record.validate(original, started)?;
            if operation != record.exact.dispatch.operation_id
                || reference != original.reference
                || commitment != record.digest()?
                || !inventory
                    .results
                    .iter()
                    .any(|r| r.authorization_id == authorization)
            {
                return Err(JournalError::InvalidBinding);
            }
            inventory.born_dispatch_requests.push((
                operation,
                authorization,
                reference,
                commitment,
            ));
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (operation, authorization, reference, commitment, raw);
            return Err(JournalError::ConstructionHistoryUnsupported);
        }
    }
    Ok(inventory)
}

#[cfg(test)]
#[path = "named_recipient_inventory_tests.rs"]
mod tests;

fn validate_manifest_terms(
    c: &Connection,
    profile: &NamedRecipientProfileRecordV1,
    original: &NamedRecipientOriginalRecordV1,
    manifest: &AcceptedManifestRecord,
) -> Result<()> {
    let t = &original.terms;
    let enrollment = storage::read_enrollment(c, &profile.enrollment_ref)?
        .ok_or(JournalError::InvalidBinding)?;
    let p = manifest.proposal()?;
    let owner = p
        .manifest()
        .participants
        .iter()
        .find(|owner| {
            owner.account_id == t.account_id && owner.participant_id == enrollment.participant_id()
        })
        .ok_or(JournalError::InvalidBinding)?;
    let mut expected = p
        .manifest()
        .inputs
        .iter()
        .filter(|input| input.account_id == t.account_id)
        .map(|input| (input.input_id.as_str(), input.amount.as_zatoshis()))
        .collect::<Vec<_>>();
    let mut actual = t
        .inputs
        .iter()
        .map(|input| (input.input_id.as_str(), input.value_zatoshis))
        .collect::<Vec<_>>();
    expected.sort();
    actual.sort();
    if t.agreement_id != enrollment.agreement_id()
        || t.agreement_id != p.manifest().agreement.agreement_id
        || t.obligation_id != p.manifest().agreement.obligation_id
        || t.network_profile_id != p.manifest().agreement.network_profile_id
        || t.proposal_id != p.input().proposal_id
        || t.proposal_revision != u64::from(p.manifest().agreement.revision)
        || t.fee_share_zatoshis != owner.fee_share.as_zatoshis()
        || t.transaction_fee_zatoshis != p.manifest().transaction_fee.as_zatoshis()
        || t.transaction_expiry_height != p.manifest().expiry_height
        || t.maximum_debit_zatoshis > owner.maximum_net_debit.as_zatoshis()
        || p.accounting()
            .participant_net_debits
            .get(&owner.participant_id)
            .map(|amount| amount.as_zatoshis())
            != Some(t.maximum_debit_zatoshis)
        || expected != actual
        || p.input()
            .artifact_digest
            .as_ref()
            .is_some_and(|d| d != &t.artifact_digest)
        || p.input()
            .effects_commitment
            .as_ref()
            .is_some_and(|d| d != &t.effects_digest)
    {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}
