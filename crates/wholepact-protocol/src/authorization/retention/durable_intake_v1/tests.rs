//! Never-funded cryptographic and protected-storage fixtures. These tests do not
//! authenticate engine intake, run native IPC, sign with user keys, or settle.
use super::*;
use orchard::keys::{SpendAuthorizingKey, SpendingKey};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use std::{cell::Cell, os::unix::fs::PermissionsExt, path::PathBuf};
use wholepact_storage_security::{DatabaseKey, create_encrypted, open_encrypted};

const LIMITS: ProvingLimits = ProvingLimits { maximum_actions: 8 };
const UNION_KEY: &str = "synthetic-union-original-key";

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wholepact-durable-intake-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .unwrap().as_nanos(),
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn journal(&self, name: &str) -> SignedResultJournal {
        SignedResultJournal::from_encrypted_connection(
            create_encrypted(self.0.join(name), &DatabaseKey::from_bytes([0x49; 32])).unwrap(),
        ).unwrap()
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Consent;
impl SignedRetentionConsent for Consent {
    fn permits(&self, scope: &SignedRetentionScope) -> bool {
        scope.context.principal_id == "synthetic-controller"
            && scope.context.local_operator == "synthetic-local-prover"
            && scope.context.retention_policy == "Temporary encrypted synthetic test"
    }
}

fn context() -> SignedCandidateContext {
    SignedCandidateContext {
        principal_id: "synthetic-controller".into(),
        candidate_id: "synthetic-candidate".into(),
        proof_job_id: "synthetic-proof".into(),
        checkpoint_scope_digest: "11".repeat(32),
        proved_artifact_digest: "22".repeat(32),
        manifest_digest: "33".repeat(32),
        review_binding: "44".repeat(32),
        delivery_provenance_digest: "55".repeat(32),
        account_ids: vec!["synthetic-owner-0".into(), "synthetic-owner-1".into()],
        local_operator: "synthetic-local-prover".into(),
        purpose: "Synthetic local resumed signature retention".into(),
        retention_policy: "Temporary encrypted synthetic test".into(),
    }
}
fn reference(number: u8) -> RetainedIntakeRefV1 {
    RetainedIntakeRefV1 {
        result_id: format!("signed-{}", format!("{number:02x}").repeat(32)),
        request_digest: "66".repeat(32),
        signed_candidate_digest: "77".repeat(32),
        delivery_provenance_digest: "88".repeat(32),
    }
}
fn union_context(original: &SignedCandidateContext, refs: &[RetainedIntakeRefV1]) -> SignedCandidateContext {
    let mut result = original.clone();
    result.delivery_provenance_digest = retained_source_set_digest_v1(refs).unwrap();
    result
}

#[test]
fn source_refs_and_saved_scopes_are_strict_data_not_grants() {
    let first = reference(1);
    let second = reference(2);
    let digest = retained_source_set_digest_v1(&[first.clone(), second.clone()]).unwrap();
    assert_eq!(digest, retained_source_set_digest_v1(&[second.clone(), first.clone()]).unwrap());
    assert!(retained_source_set_digest_v1(&[]).is_err());
    assert!(retained_source_set_digest_v1(&[first.clone(), first.clone()]).is_err());
    assert!(retained_source_set_digest_v1(&vec![first.clone(); 65]).is_err());
    for field in ["result_id", "request_digest", "signed_candidate_digest", "delivery_provenance_digest"] {
        let mut value = serde_json::to_value(&first).unwrap();
        value[field] = "FORGED".into();
        let malformed: RetainedIntakeRefV1 = serde_json::from_value(value).unwrap();
        assert!(retained_source_set_digest_v1(&[malformed]).is_err());
    }
    let mut value = serde_json::to_value(&first).unwrap();
    value["verified"] = true.into();
    assert!(serde_json::from_value::<RetainedIntakeRefV1>(value).is_err());
    let encoded = serde_json::to_string(&first).unwrap();
    let duplicated = encoded.replacen('{', "{\"request_digest\":\"forged\",", 1);
    assert!(serde_json::from_str::<RetainedIntakeRefV1>(&duplicated).is_err());

    let scope = SignedRetentionScope { context: context(), signature_set_digest: "99".repeat(32) };
    let encoded = serde_json::to_vec(&scope).unwrap();
    assert!(decode_scope(&encoded).is_ok());
    let mut value = serde_json::to_value(&scope).unwrap();
    value["context"]["verified"] = true.into();
    assert!(decode_scope(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = serde_json::to_value(&scope).unwrap();
    value["authorization_allowed"] = true.into();
    assert!(decode_scope(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(decode_scope(&serde_json::to_vec_pretty(&scope).unwrap()).is_err());

    assert!(decode_signatures(&[]).is_err());
    assert!(decode_signatures(&[0; 79]).is_err());
    assert!(decode_signatures(&[0; 81]).is_err());
    assert!(decode_signatures(&vec![0; 65 * 80]).is_err());
    let signatures = RetainedSignatures(vec![
        ExternalSignature { participant_index: 0, action_index: 1, signature: [1; 64] },
        ExternalSignature { participant_index: 1, action_index: 2, signature: [2; 64] },
    ]);
    let encoded = encode_signatures(&signatures.0).unwrap();
    assert_eq!(decode_signatures(&encoded).unwrap().0.len(), 2);
    let mut unordered = encoded.to_vec();
    unordered.rotate_left(80);
    assert!(decode_signatures(&unordered).is_err());
    let mut repeated = encoded[..80].to_vec();
    repeated.extend_from_slice(&encoded[..80]);
    assert!(decode_signatures(&repeated).is_err());
}

#[test]
fn saved_subsets_resume_with_full_verification_and_fail_closed() {
    let dir = Temp::new();
    let mut journal = dir.journal("original.db");
    let fixture = crate::synthetic::review_fixture().unwrap();
    let review = crate::review::verify_review(&fixture.pczt_bytes, &fixture.policy).unwrap();
    let proved = crate::proving::prove_reviewed(
        &fixture.pczt_bytes, &fixture.policy, review.review_binding(), LIMITS,
    ).unwrap();
    let base = Zeroizing::new(proved.pczt_bytes);
    let policy = fixture.policy;
    let mut original = context();
    original.proved_artifact_digest = hash(&base);
    original.manifest_digest = hex::encode(policy.manifest_digest);
    original.review_binding = review.review_binding().into();
    original.account_ids = policy.participants.iter().map(|p| p.account_id.clone()).collect();
    let mut refs = Vec::new();
    for owner in 0..2 {
        let action_index = policy.inputs.iter().find(|i| i.participant_index == owner).unwrap().action_index;
        let mut signer = pczt::roles::signer::Signer::new(pczt::Pczt::parse(&base).unwrap()).unwrap();
        let key = SpendingKey::from_bytes([owner as u8 + 1; 32]).unwrap();
        signer.sign_ironwood(UnwrapErr(SysRng), action_index, &SpendAuthorizingKey::from(&key)).unwrap();
        let signed = signer.finish();
        let signatures = RetainedSignatures(vec![ExternalSignature {
            participant_index: owner, action_index,
            signature: signed.ironwood().actions()[action_index].spend().spend_auth_sig().unwrap(),
        }]);
        let mut scope = original.clone();
        scope.delivery_provenance_digest = format!("{:02x}", owner + 1).repeat(32);
        let summary = journal.retain(
            scope.clone(), &format!("synthetic-owner-intake-{owner}"), &base, &policy,
            &signatures.0, LIMITS, &Consent,
        ).unwrap();
        assert_eq!(summary.inspection.verified_real_inputs, 1);
        assert!(!summary.inspection.signatures_complete);
        refs.push(RetainedIntakeRefV1 {
            result_id: summary.result_id, request_digest: summary.request_digest,
            signed_candidate_digest: summary.signed_candidate_digest,
            delivery_provenance_digest: scope.delivery_provenance_digest,
        });
    }

    // Drop all initial signers/subset arrays, close SQLCipher, and resume solely
    // from the reopened original journal and engine-style data references.
    drop(journal);
    journal = SignedResultJournal::from_encrypted_connection(
        open_encrypted(dir.0.join("original.db"), &DatabaseKey::from_bytes([0x49; 32])).unwrap(),
    ).unwrap();
    let context = union_context(&original, &refs);
    let union = journal.load_verified_union(context.clone(), &refs, &base, &policy, LIMITS, &Consent).unwrap();
    assert!(union.inspection().signatures_complete);
    assert!(union.inspection().proof_verified);
    assert!(union.inspection().exact_candidate_preserved);
    assert!(!union.inspection().authorization_allowed);
    assert!(!union.inspection().distribution_allowed);
    assert!(!union.inspection().chain_validated);
    let before_read = journal.connection.lock().unwrap().total_changes();
    assert!(matches!(union.verify_completed_existing(UNION_KEY), Err(RetentionError::IntentNotFound)));
    assert_eq!(journal.connection.lock().unwrap().total_changes(), before_read);
    let retained = union.retain(UNION_KEY).unwrap();
    let after_retention = journal.connection.lock().unwrap().total_changes();
    let completed = union.verify_completed_existing(UNION_KEY).unwrap();
    assert_eq!(completed.result_id, retained.result_id);
    assert_eq!(completed.request_digest, retained.request_digest);
    assert_eq!(completed.signed_candidate_digest, retained.signed_candidate_digest);
    assert_eq!(journal.connection.lock().unwrap().total_changes(), after_retention);
    assert!(!retained.exact_replay);
    assert!(!retained.transaction_extracted);
    assert!(!retained.authorization_allowed);
    assert!(!retained.distribution_allowed);
    assert!(union.retain(UNION_KEY).unwrap().exact_replay);
    drop(union);
    let reversed = vec![refs[1].clone(), refs[0].clone()];
    let replay = journal.load_verified_union(context.clone(), &reversed, &base, &policy, LIMITS, &Consent)
        .unwrap().retain(UNION_KEY).unwrap();
    assert!(replay.exact_replay);
    assert_eq!(replay.signed_candidate_digest, retained.signed_candidate_digest);

    let partial_context = union_context(&original, &refs[..1]);
    let partial = journal.load_verified_union(partial_context, &refs[..1], &base, &policy, LIMITS, &Consent).unwrap();
    assert!(!partial.inspection().signatures_complete);
    assert_eq!(partial.retain(UNION_KEY).err(), Some(RetentionError::IdempotencyConflict));
    let partial_result = partial.retain("synthetic-partial-union-key").unwrap();
    assert!(!partial_result.inspection.signatures_complete);
    assert!(partial.retain("synthetic-partial-union-key").unwrap().exact_replay);
    #[cfg(feature = "transaction-checkpoint")]
    {
        use super::super::transaction::{
            LocalTransactionCheckpoint, TransactionCheckpointJournal,
            TransactionRetentionConsent, TransactionRetentionScope,
        };
        struct TransactionConsent;
        impl TransactionRetentionConsent for TransactionConsent {
            fn permits(&self, scope: &TransactionRetentionScope) -> bool {
                Consent.permits(&scope.signed_scope)
            }
        }
        let transactions = TransactionCheckpointJournal::from_encrypted_connection(
            create_encrypted(dir.0.join("transactions.db"), &DatabaseKey::from_bytes([0x4a; 32])).unwrap(),
        ).unwrap();
        let local = || LocalTransactionCheckpoint { journal: &transactions, consent: &TransactionConsent };
        assert_eq!(partial.checkpoint_transaction("synthetic-partial-union-key", local()).err(), Some(RetentionError::IncompleteSignatures));
        let complete = journal.load_verified_union(context.clone(), &refs, &base, &policy, LIMITS, &Consent).unwrap();
        let transaction = complete.checkpoint_transaction(UNION_KEY, local()).unwrap();
        assert!(transaction.transaction_extracted);
        assert!(transaction.cryptographic_transaction_verified);
        assert!(!transaction.exact_replay);
        assert!(!transaction.authorization_allowed);
        assert!(!transaction.distribution_allowed);
        assert!(!transaction.release_allowed);
        let replay = complete.checkpoint_transaction(UNION_KEY, local()).unwrap();
        assert!(replay.exact_replay);
        assert_eq!(replay.transaction_digest, transaction.transaction_digest);
        assert_eq!(replay.txid, transaction.txid);
        assert_eq!(replay.checkpoint_id, transaction.checkpoint_id);
    }
    drop(partial);

    let empty = dir.journal("unrelated.db");
    assert_eq!(empty.load_verified_union(context.clone(), &refs, &base, &policy, LIMITS, &Consent).err(), Some(RetentionError::IntentNotFound));
    for field in ["result_id", "request_digest", "signed_candidate_digest", "delivery_provenance_digest"] {
        let mut value = serde_json::to_value(&refs[0]).unwrap();
        value[field] = (if field == "result_id" { format!("signed-{}", "fe".repeat(32)) } else { "fe".repeat(32) }).into();
        let changed = vec![serde_json::from_value::<RetainedIntakeRefV1>(value).unwrap(), refs[1].clone()];
        let target = union_context(&original, &changed);
        assert!(journal.load_verified_union(target, &changed, &base, &policy, LIMITS, &Consent).is_err());
    }
    for field in 0..12 {
        let mut changed = context.clone();
        match field {
            0 => changed.principal_id = "wrong-controller".into(),
            1 => changed.candidate_id = "wrong-candidate".into(),
            2 => changed.proof_job_id = "wrong-proof".into(),
            3 => changed.checkpoint_scope_digest = "fe".repeat(32),
            4 => changed.proved_artifact_digest = "fe".repeat(32),
            5 => changed.manifest_digest = "fe".repeat(32),
            6 => changed.review_binding = "fe".repeat(32),
            7 => changed.account_ids[0] = "wrong-account".into(),
            8 => changed.local_operator = "wrong-operator".into(),
            9 => changed.purpose = "unapproved-purpose".into(),
            10 => changed.retention_policy = "unapproved-retention".into(),
            _ => changed.delivery_provenance_digest = "fe".repeat(32),
        }
        assert!(journal.load_verified_union(changed, &refs, &base, &policy, LIMITS, &Consent).is_err());
    }
    let mut wrong_base = base.to_vec();
    wrong_base[0] ^= 1;
    assert!(journal.load_verified_union(context.clone(), &refs, &wrong_base, &policy, LIMITS, &Consent).is_err());
    for change in 0..5 {
        let mut wrong = policy.clone();
        match change {
            0 => wrong.participants[0].maximum_net_debit_zatoshis += 1,
            1 => wrong.inputs[0].participant_index = 1 - wrong.inputs[0].participant_index,
            2 => wrong.outputs[0].value_zatoshis += 1,
            3 => wrong.exact_fee_zatoshis += 1,
            _ => wrong.anchor[0] ^= 1,
        }
        assert!(journal.load_verified_union(context.clone(), &refs, &base, &wrong, LIMITS, &Consent).is_err());
    }
    assert!(journal.load_verified_union(context.clone(), &refs, &base, &policy, ProvingLimits { maximum_actions: 7 }, &Consent).is_err());
    assert!(journal.load_verified_union(context.clone(), &refs, &base, &policy, ProvingLimits { maximum_actions: 0 }, &Consent).is_err());

    // A union and its original source overlap even if every signature is valid.
    let overlapping = vec![refs[0].clone(), RetainedIntakeRefV1 {
        result_id: retained.result_id.clone(), request_digest: retained.request_digest.clone(),
        signed_candidate_digest: retained.signed_candidate_digest.clone(),
        delivery_provenance_digest: context.delivery_provenance_digest.clone(),
    }];
    assert!(journal.load_verified_union(union_context(&original, &overlapping), &overlapping, &base, &policy, LIMITS, &Consent).is_err());

    struct Revocable { allowed: Cell<bool>, denied_provenance: Option<String> }
    impl SignedRetentionConsent for Revocable {
        fn permits(&self, scope: &SignedRetentionScope) -> bool {
            self.allowed.get() && Consent.permits(scope)
                && self.denied_provenance.as_deref() != Some(scope.context.delivery_provenance_digest.as_str())
        }
    }
    for denied in [&refs[0].delivery_provenance_digest, &refs[1].delivery_provenance_digest, &context.delivery_provenance_digest] {
        let consent = Revocable { allowed: Cell::new(true), denied_provenance: Some(denied.clone()) };
        assert_eq!(journal.load_verified_union(context.clone(), &refs, &base, &policy, LIMITS, &consent).err(), Some(RetentionError::ConsentDenied));
    }
    let consent = Revocable { allowed: Cell::new(true), denied_provenance: None };
    let handle = journal.load_verified_union(context.clone(), &refs, &base, &policy, LIMITS, &consent).unwrap();
    consent.allowed.set(false);
    assert_eq!(handle.retain("synthetic-revoked-union-key").err(), Some(RetentionError::ConsentDenied));
    drop(handle);

    // Inject damaged copies into separate protected synthetic journals. This is
    // fault injection, not a production write, import, or recovery path.
    let row = saved_row(&journal, &refs[0].result_id);
    for mutation in 0..8 {
        let damaged = dir.journal(&format!("fault-{mutation}.db"));
        let mut row = row.clone();
        let mut reference = refs[0].clone();
        match mutation {
            0 => row.signatures[16] ^= 1,
            1 => row.bytes[0] ^= 1,
            2 => row.scope = br#"{"context":{},"signature_set_digest":"invalid","verified":true}"#.to_vec(),
            3 => row.scope.push(b' '),
            // Re-hash the damaged signature/action/owner. Hash equality alone
            // cannot replace the maintained signature and complete-policy check.
            4..=6 => {
                match mutation {
                    4 => row.signatures[16] ^= 1,
                    5 => row.signatures[..8].copy_from_slice(&99_u64.to_le_bytes()),
                    _ => row.signatures[8..16].copy_from_slice(&99_u64.to_le_bytes()),
                }
                let mut scope = decode_scope(&row.scope).unwrap();
                scope.signature_set_digest = hash(&row.signatures);
                row.scope = serde_json::to_vec(&scope).unwrap();
                row.request = framed(&[&row.scope, &row.signatures, &(LIMITS.maximum_actions as u64).to_le_bytes()]);
                reference.request_digest = row.request.clone();
            }
            _ => row.principal = "wrong-saved-controller".into(),
        }
        insert_row(&damaged, &row, true);
        let refs = [reference];
        assert!(damaged.load_verified_union(union_context(&original, &refs), &refs, &base, &policy, LIMITS, &Consent).is_err());
    }
    let interrupted = dir.journal("intent-without-result.db");
    insert_row(&interrupted, &row, false);
    assert_eq!(interrupted.load_verified_union(union_context(&original, &refs[..1]), &refs[..1], &base, &policy, LIMITS, &Consent).err(), Some(RetentionError::RecoveryRequired));

    let c = journal.connection.lock().unwrap();
    assert_eq!(c.query_row("SELECT count(*) FROM signed_intents", [], |r| r.get::<_, i64>(0)).unwrap(), 4);
    assert_eq!(c.query_row("SELECT count(*) FROM signed_results", [], |r| r.get::<_, i64>(0)).unwrap(), 4);
    assert!(c.execute("UPDATE signed_results SET digest='forged'", []).is_err());
    assert!(c.execute("DELETE FROM signed_intents", []).is_err());
}

#[derive(Clone)]
struct SavedRow {
    result_id: String,
    principal: String,
    key: String,
    request: String,
    scope: Vec<u8>,
    signatures: Vec<u8>,
    bytes: Vec<u8>,
    digest: String,
}
impl Drop for SavedRow {
    fn drop(&mut self) {
        self.scope.zeroize();
        self.signatures.zeroize();
        self.bytes.zeroize();
    }
}
fn saved_row(journal: &SignedResultJournal, id: &str) -> SavedRow {
    journal.connection.lock().unwrap().query_row(
        "SELECT i.result_id,i.principal_id,i.idem_key,i.request_digest,i.scope,i.signatures,r.bytes,r.digest FROM signed_intents i JOIN signed_results r ON r.result_id=i.result_id WHERE i.result_id=?1",
        [id], |r| Ok(SavedRow {
            result_id: r.get(0)?, principal: r.get(1)?, key: r.get(2)?, request: r.get(3)?,
            scope: r.get(4)?, signatures: r.get(5)?, bytes: r.get(6)?, digest: r.get(7)?,
        }),
    ).unwrap()
}
fn insert_row(journal: &SignedResultJournal, row: &SavedRow, completed: bool) {
    let c = journal.connection.lock().unwrap();
    c.execute(
        "INSERT INTO signed_intents(result_id,principal_id,idem_key,request_digest,scope,signatures) VALUES (?1,?2,?3,?4,?5,?6)",
        params![row.result_id, row.principal, row.key, row.request, row.scope, row.signatures],
    ).unwrap();
    if completed {
        c.execute("INSERT INTO signed_results(result_id,bytes,digest) VALUES (?1,?2,?3)", params![row.result_id, row.bytes, row.digest]).unwrap();
    }
}
