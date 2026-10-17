//! One focused native decision imports the already-enrolled HPKE key into the
//! original encrypted authority journal. No key generation/reset or new files.
use crate::{
    born_offline_artifacts_v1::*,
    native_witness_owner::NativeBornOfflineArtifactsDecisionV1,
    offline_witness_transport_v1 as transport,
    policy::Event,
    witness_locator::{NamespaceOpenInput, open_born_history},
    *,
};
use rusqlite::{Transaction, TransactionBehavior, params};
use std::path::Path;

pub(crate) struct BornOfflineArtifactsProposalV1 {
    journal: AuthorityJournal,
    key_file: String,
    secret: Zeroizing<[u8; 32]>,
    record: BornOfflineArtifactRecordV1,
    original_enrollment: crate::born_offline_enrollment_v1::BornOfflineEnrollmentV1,
    reviewed_stamp: crate::journal::NamespaceJournalStamp,
    existing: Option<BornOfflineArtifactsAuditV1>,
}
#[derive(Clone)]
pub(crate) struct BornOfflineArtifactsAuditV1 {
    pub(crate) original_record: BornOfflineArtifactRecordV1,
    pub(crate) committed_head: AuthorityHead,
}
impl BornOfflineArtifactsProposalV1 {
    pub(crate) fn check_current(&self) -> Result<()> {
        let owner = self
            .journal
            .born_owner
            .as_ref()
            .ok_or(AuthorityError::Permission)?;
        owner.check_mutation_current()?;
        if owner.namespace_binding_digest_v1()? != self.record.binding.namespace_binding_digest {
            return Err(AuthorityError::InvalidBinding);
        }
        let actual = wholepact_storage_security::witness_namespace_fs::read_existing_storage_key(
            Path::new(&self.key_file),
        )?;
        if *actual != *self.secret {
            return Err(AuthorityError::Conflict);
        }
        let c = self
            .journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        let ledger = crate::journal::load(&tx)?;
        if ledger.born_offline_enrollment_v1()?.map(|e| &e.enrollment)
            != Some(&self.original_enrollment)
        {
            return Err(AuthorityError::Conflict);
        }
        if crate::journal::namespace_account_stamp(&tx, &ledger.policy)?.0 != self.reviewed_stamp {
            return Err(AuthorityError::StaleHead);
        }
        if let Some(audit) = &self.existing {
            let original_secret = Zeroizing::new(tx.query_row(
                "SELECT secret FROM authority_born_offline_artifacts WHERE singleton=1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )?);
            if original_secret.as_slice() != self.secret.as_slice() {
                return Err(AuthorityError::Conflict);
            }
            if ledger.born_offline_artifacts_v1()? != Some(&audit.original_record) {
                return Err(AuthorityError::Conflict);
            }
            Ok(())
        } else {
            ledger.validate_new_born_offline_artifacts_v1(&self.record, now_ms()?)
        }
    }
    pub(crate) fn review_digest(&self) -> Result<String> {
        self.check_current()?;
        Ok(self.record.native_review_digest.clone())
    }
    pub(crate) fn first_commit_deadline_ms(&self) -> Option<u64> {
        self.existing
            .is_none()
            .then_some(self.record.binding.first_commit_deadline_ms)
    }
    pub(crate) fn display(&self) -> Result<String> {
        self.check_current()?;
        serde_json::to_string_pretty(&serde_json::json!({
            "operation":"Import existing born offline transport key and create retained private mailboxes",
            "notice":"This is persistent local access creation, not a payment. Only the already-enrolled witness HPKE secret is imported from the independently selected protected file. Its public key, signer peer and assurance remain exactly pinned by the original enrollment. The original encrypted authority journal gains immutable key storage, retained inbox/outbox and original retry records atomically. No replacement, reset, budget increase, new key, new namespace or extra mailbox file is permitted. Keep the complete encrypted namespace backup together. Archive restore remains historical only. Cancel or focus loss before publication revokes this decision. Do not approve if you do not intend this persistent import.",
            "existing_key_file": self.key_file,
            "binding":self.record.binding,
            "original_enrollment_policy_assurance_and_session":self.original_enrollment,
            "native_review_digest":self.record.native_review_digest,
            "full_reviewed_retention_digest":self.reviewed_stamp.retained_state_digest,
            "exact_existing_installation_audit_only":self.existing.is_some(),
            "financial_execution_available":false
        })).map_err(|_| AuthorityError::InvalidBinding)
    }
}

pub(crate) fn prepare_born_offline_artifacts_v1(
    input: NamespaceOpenInput,
    key_file: String,
    signer_hex: String,
) -> Result<BornOfflineArtifactsProposalV1> {
    if key_file.len() > 4096 || !Path::new(&key_file).is_absolute() {
        return Err(AuthorityError::InvalidBinding);
    }
    hash(&signer_hex)?;
    let signer: [u8; 32] = hex::decode(&signer_hex)
        .map_err(|_| AuthorityError::InvalidBinding)?
        .try_into()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    transport::TransportPublicKey::from_bytes(signer)
        .map_err(|_| AuthorityError::Authentication)?;
    let secret = wholepact_storage_security::witness_namespace_fs::read_existing_storage_key(
        Path::new(&key_file),
    )?;
    let public = transport::TransportSecret::from_bytes(*secret)
        .and_then(|s| s.public_key())
        .map_err(|_| AuthorityError::Authentication)?;
    let journal = open_born_history(input)?;
    let owner = journal
        .born_owner
        .as_ref()
        .ok_or(AuthorityError::Permission)?;
    owner.check_mutation_current()?;
    let namespace = owner.namespace_binding_digest_v1()?;
    let (mut record, stamp, existing, original_enrollment) = {
        let c = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Deferred)?;
        let ledger = crate::journal::load(&tx)?;
        let stamp = crate::journal::namespace_account_stamp(&tx, &ledger.policy)?.0;
        let original_enrollment = ledger
            .born_offline_enrollment_v1()?
            .ok_or(AuthorityError::Permission)?
            .enrollment
            .clone();
        let old = ledger.born_offline_artifacts_v1()?;
        if let Some(old) = old {
            if old.binding.witness_public_key_hex != hex::encode(public.as_bytes())
                || old.binding.offline_signer_public_key_hex != signer_hex
                || old.binding.namespace_binding_digest != namespace
            {
                return Err(AuthorityError::Conflict);
            }
            let (_, _, MutationResult::Controlled(snapshot)) = ledger
                .operations
                .get(&old.binding.owner_operation_id()?)
                .ok_or(AuthorityError::CorruptHistory)?
            else {
                return Err(AuthorityError::CorruptHistory);
            };
            (
                old.clone(),
                stamp,
                Some(BornOfflineArtifactsAuditV1 {
                    original_record: old.clone(),
                    committed_head: snapshot.head.clone(),
                }),
                original_enrollment,
            )
        } else {
            let now = now_ms()?;
            let e = ledger.require_born_offline_original_session_v1(now)?;
            let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
            if version != 6 {
                return Err(AuthorityError::UnsupportedVersion);
            }
            let binding = BornOfflineArtifactBindingV1 {
                version: 1,
                enrollment_digest: e.digest()?,
                namespace_binding_digest: namespace,
                witness_public_key_hex: hex::encode(public.as_bytes()),
                offline_signer_public_key_hex: signer_hex,
                expected_head: ledger.snapshot.head.clone(),
                issued_at_ms: now,
                first_commit_deadline_ms: now
                    .checked_add(120_000)
                    .ok_or(AuthorityError::Limit)?
                    .min(e.policy.expires_at_ms),
            };
            binding.validate_enrollment(e)?;
            (
                BornOfflineArtifactRecordV1 {
                    binding,
                    native_review_digest: "0".repeat(64),
                },
                stamp,
                None,
                original_enrollment,
            )
        }
    };
    // Exact existing imports are historical inspection; do not change their
    // immutable review digest or issue a new operation/deadline on restart.
    if existing.is_none() {
        record.native_review_digest = digest(
            "wholepact:native-born-offline-artifacts-review:v1",
            &(&record.binding, &key_file, &stamp),
        )?;
    }
    let proposal = BornOfflineArtifactsProposalV1 {
        journal,
        key_file,
        secret,
        record,
        original_enrollment,
        reviewed_stamp: stamp,
        existing,
    };
    proposal.check_current()?;
    Ok(proposal)
}

pub(crate) fn commit_born_offline_artifacts_v1(
    decision: NativeBornOfflineArtifactsDecisionV1,
) -> Result<BornOfflineArtifactsAuditV1> {
    let (p, lease) = decision.into_parts();
    lease.check_current()?;
    if lease.reviewed_digest() != p.record.native_review_digest {
        return Err(AuthorityError::Permission);
    }
    p.check_current()?;
    if let Some(existing) = &p.existing {
        lease.check_current()?;
        return Ok(existing.clone());
    }
    let owner = p
        .journal
        .born_owner
        .as_ref()
        .ok_or(AuthorityError::Permission)?;
    owner.check_mutation_current()?;
    let c = p
        .journal
        .connection
        .lock()
        .map_err(|_| AuthorityError::Storage)?;
    let tx = Transaction::new_unchecked(c.connection(), TransactionBehavior::Immediate)?;
    lease.check_current()?;
    let mut ledger = crate::journal::load(&tx)?;
    if crate::journal::namespace_account_stamp(&tx, &ledger.policy)?.0 != p.reviewed_stamp {
        return Err(AuthorityError::StaleHead);
    }
    let now = now_ms()?;
    ledger.validate_new_born_offline_artifacts_v1(&p.record, now)?;
    let event = Event {
        mutation: AuthorityMutation::OwnerControl(OwnerControlRequest {
            operation_id: p.record.binding.owner_operation_id()?,
            account_id: ledger.policy.account_id.clone(),
            network_profile_id: ledger.policy.network_profile_id.clone(),
            expected_head: ledger.snapshot.head.clone(),
            writer_epoch: ledger.snapshot.writer_epoch,
            control: OwnerControl::InstallBornOfflineArtifactsV1 {
                record: Box::new(p.record.clone()),
            },
        }),
        authenticated_certificate_digest: ledger.policy.owner_certificate_digest.clone(),
        witness_time_ms: now,
        writer_session_id: None,
        original_request_link: None,
    };
    let previous = ledger.snapshot.head.digest.clone();
    ledger.apply(&event)?;
    let payload = encode(&event)?;
    let bytes: u64 = tx.query_row(
        "SELECT coalesce(sum(length(payload)),0) FROM authority_events",
        [],
        |r| r.get(0),
    )?;
    if bytes
        .checked_add(payload.len() as u64)
        .filter(|n| *n <= MAX_JOURNAL_BYTES)
        .is_none()
    {
        return Err(AuthorityError::Limit);
    }
    let audit = BornOfflineArtifactsAuditV1 {
        original_record: p.record.clone(),
        committed_head: ledger.snapshot.head.clone(),
    };
    // This private function installs all schema/rows and the owner event in the
    // SAME transaction. No intermediate v7-empty or key-only state can survive.
    crate::journal::install_born_artifact_rows_v1(&tx, &p.record, &p.secret)?;
    tx.execute(
        "INSERT INTO authority_events VALUES(?1,?2,?3,?4,?5)",
        params![
            ledger.snapshot.head.sequence,
            event.mutation.operation_id(),
            previous,
            ledger.snapshot.head.digest,
            payload.as_slice()
        ],
    )?;
    crate::journal::verify_born_artifact_schema_v1(&tx)?;
    // All schema work, replay, retained-key comparison and audit construction
    // stays revocable. Cancellation here rolls back the entire staged upgrade.
    owner.check_mutation_current()?;
    let current_key = wholepact_storage_security::witness_namespace_fs::read_existing_storage_key(
        Path::new(&p.key_file),
    )?;
    if *current_key != *p.secret {
        return Err(AuthorityError::Conflict);
    }
    lease.check_current()?;
    let publication = lease.publication_lease()?;
    publication.check_current()?;
    if publication.reviewed_digest() != p.record.native_review_digest
        || publication.admitted_at_ms() < now
    {
        return Err(AuthorityError::Expired);
    }
    p.record
        .binding
        .require_first_commit_time(publication.admitted_at_ms())?;
    publication.check_current()?;
    let final_now = now_ms()?;
    if final_now < publication.admitted_at_ms() {
        return Err(AuthorityError::Expired);
    }
    p.record.binding.require_first_commit_time(final_now)?;
    tx.commit().map_err(|_| AuthorityError::Uncertain)?;
    owner
        .check_mutation_current()
        .map_err(|_| AuthorityError::Uncertain)?;
    publication
        .check_current()
        .map_err(|_| AuthorityError::Uncertain)?;
    Ok(audit)
}
