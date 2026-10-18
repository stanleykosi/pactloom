//! Modeled inert native audit around real synthetic signed authority replay.
//! These tests qualify schema, exact lineage and encrypted preservation only.
//! They do not issue native read/construction owners or execute a provider read.
use super::*;
use crate as signer;
#[path = "common_context_audit_fixture.rs"]
pub(super) mod fixture;
use std::collections::{BTreeMap, BTreeSet};
use wholepact_storage_security::{DatabaseKey, bundle::*};

#[test]
fn modeled_common_context_lineage_retains_charge_and_rejects_omissions() {
    let (inventory, evidence) = fixture::fixture();
    let history = &evidence.complete_history.construction;
    inventory.validate_against(history).unwrap();
    assert!(history.retained_debit_zatoshis().unwrap() > 0);
    assert_eq!(
        evidence
            .complete_history
            .conservative_debit_zatoshis()
            .unwrap(),
        history.retained_debit_zatoshis().unwrap()
    );
    assert!(inventory.missing_local_phases(history).unwrap().is_empty());
    for retained in [
        vec![],
        vec!["read_admitted"],
        vec!["read_admitted", "reserved"],
    ] {
        let mut changed = inventory.clone();
        changed.rows.retain(|r| retained.contains(&r.phase()));
        changed.validate_against(history).unwrap();
        let missing = changed.missing_local_phases(history).unwrap();
        assert_eq!(missing.len(), 1);
        assert!(missing[0].missing_consumed);
        assert_eq!(missing[0].missing_reserved, !retained.contains(&"reserved"));
        assert_eq!(
            history.retained_debit_zatoshis().unwrap(),
            evidence
                .complete_history
                .conservative_debit_zatoshis()
                .unwrap()
        );
    }
    for phase in ["read_admitted", "reserved"] {
        let mut orphan = inventory.clone();
        orphan.rows.retain(|r| r.phase() != phase);
        assert!(orphan.validate_against(history).is_err());
    }
    let mut duplicate = inventory.clone();
    duplicate.rows.push(duplicate.rows[0].clone());
    assert!(duplicate.validate_against(history).is_err());
    let mut changed = inventory.clone();
    let CommonContextSignerAuditV1::Consumed {
        evidence: native, ..
    } = &mut changed.rows[0]
    else {
        panic!("canonical consumed first")
    };
    native.native_review_digest = "ee".repeat(32);
    assert!(changed.validate_against(history).is_err());
    assert!(
        evidence
            .complete_history
            .require_financial_activation_supported()
            .is_err()
    );
}

#[test]
fn modeled_common_context_encrypted_journal_backup_preserves_every_original_phase() {
    let (inventory, evidence) = fixture::fixture();
    let account = &evidence.request.account_id;
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("never-funded-synthetic-journal.sqlite");
    let key = DatabaseKey::from_bytes([71; 32]);
    let private_directory = crate::files::PrivateDirectory::open(dir.path()).unwrap();
    let journal = SignerConsentJournal::create_encrypted(
        &path,
        &key,
        account,
        1,
        false,
        &private_directory
            .signer_journal_source_owner_for_test(&path)
            .unwrap(),
    )
    .unwrap();
    for phase in ["read_admitted", "reserved", "consumed"] {
        let row = inventory.rows.iter().find(|r| r.phase() == phase).unwrap();
        journal.retain_common_context_audit_v3(row).unwrap();
    }
    let original = serde_json::to_vec(&inventory).unwrap();
    {
        let c = journal.connection.lock().unwrap();
        assert_eq!(
            serde_json::to_vec(&construction_audit_v3::read_all(&c, account).unwrap()).unwrap(),
            original
        );
        assert!(
            c.execute("DELETE FROM signer_common_context_audit_v3", [])
                .is_err()
        );
        assert!(
            c.execute(
                "UPDATE signer_common_context_audit_v3 SET phase='read_admitted'",
                []
            )
            .is_err()
        );
        assert!(offline_history::require_legacy_journal(&c).is_err());
    }
    let before = storage::capacity_estimate(&journal.connection.lock().unwrap()).unwrap();
    assert!(
        journal
            .retain_common_context_audit_v3(&inventory.rows[0])
            .is_err()
    );
    assert_eq!(
        before,
        storage::capacity_estimate(&journal.connection.lock().unwrap()).unwrap()
    );
    drop(journal);
    let journal = SignerConsentJournal::open_encrypted(
        &path,
        &key,
        account,
        &private_directory
            .signer_journal_source_owner_for_test(&path)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_vec(
            &construction_audit_v3::read_all(&journal.connection.lock().unwrap(), account).unwrap()
        )
        .unwrap(),
        original
    );
    let archive = dir.path().join("never-funded-archive.sqlite");
    let restored = dir.path().join("quarantined.sqlite");
    let archive_key = DatabaseKey::from_bytes([72; 32]);
    let restored_key = DatabaseKey::from_bytes([73; 32]);
    let adapter = journal.backup_adapter();
    let sources = [RegisteredJournal::new("signer-authority", &adapter).unwrap()];
    let coverage = Coverage {
        present: BTreeMap::from([(
            JournalKind::SignerConsentAuthority,
            vec!["signer-authority".into()],
        )]),
        absent: BTreeSet::from([
            JournalKind::CoordinationAuthority,
            JournalKind::WalletScan,
            JournalKind::ProofWitness,
            JournalKind::SignedResults,
            JournalKind::ExactTransactions,
            JournalKind::Submission,
            JournalKind::TransportInbox,
            JournalKind::TransportOutbox,
        ]),
    };
    snapshot(SnapshotRequest {
        principal_id: "synthetic-owner",
        profile_id: "synthetic-signer-profile",
        coverage,
        sources: &sources,
        destination: &archive,
        key: &archive_key,
        authority: &super::tests::BackupGate,
    })
    .unwrap();
    let report = restore(RestoreRequest {
        principal_id: "synthetic-owner",
        profile_id: "synthetic-signer-profile",
        archive: &archive,
        key: &archive_key,
        targets: &[RestoreTarget {
            component_id: "signer-authority",
            template: SignerConsentBundleAdapter::template(),
            destination: &restored,
            key: &restored_key,
        }],
        authority: &super::tests::BackupGate,
    })
    .unwrap();
    assert!(!report.authorization_allowed);
    assert!(SignerConsentJournal::open_encrypted(
        &restored,
        &restored_key,
        account,
        &private_directory
            .signer_journal_source_owner_for_test(&restored)
            .unwrap()
    )
    .is_err());
    let source = wholepact_storage_security::bundle::recovery::VerifiedSignerRecoverySource::open(
        history::HistoryOpenRequest {
            archive: &archive,
            archive_key: &archive_key,
            component_id: "signer-authority",
            restored_component: &restored,
            restored_key: &restored_key,
        },
        SignerConsentBundleAdapter::template(),
    )
    .unwrap();
    let table = source
        .tables()
        .iter()
        .find(|t| t.name() == "signer_common_context_audit_v3")
        .unwrap();
    assert_eq!(table.rows().len(), 3);
    let mut restored_rows = table
        .rows()
        .iter()
        .map(|r| {
            let wholepact_storage_security::bundle::recovery::RecoveryCell::Text(payload) =
                &r.cells()[4]
            else {
                panic!("exact text payload")
            };
            serde_json::from_str::<CommonContextSignerAuditV1>(payload).unwrap()
        })
        .collect::<Vec<_>>();
    restored_rows.sort_by_key(|r| (r.invocation_digest().unwrap(), r.phase()));
    let restored_inventory = CommonContextSignerAuditInventoryV1 {
        version: 1,
        rows: restored_rows,
    };
    assert_eq!(serde_json::to_vec(&restored_inventory).unwrap(), original);
    restored_inventory
        .validate_against(&evidence.complete_history.construction)
        .unwrap();
}

#[test]
fn reserve_only_present_lineage_rejects_changed_read_attempt_before_consume() {
    let (inventory, evidence) = fixture::fixture();
    let mut reserve_only = inventory.clone();
    reserve_only.rows.retain(|r| r.phase() != "consumed");
    reserve_only
        .validate_against(&evidence.complete_history.construction)
        .unwrap();
    for field in 0..5 {
        let mut changed = reserve_only.clone();
        let read = changed
            .rows
            .iter_mut()
            .find(|r| r.phase() == "read_admitted")
            .unwrap();
        let CommonContextSignerAuditV1::ReadAdmitted { evidence: read, .. } = read else {
            unreachable!()
        };
        match field {
            0 => read.retained_signer_intent_digest = "ab".repeat(32),
            1 => read.current_attempt_digest = "bc".repeat(32),
            2 => read.current_attempt_sequence += 1,
            3 => read.writer_session_expires_at_ms += 1,
            _ => {
                read.admitted_at_ms = read.request.admission_expires_at_ms + 1;
                read.request.admission_expires_at_ms = read.admitted_at_ms + 1;
            }
        }
        let digest = read.digest().unwrap();
        let row = changed
            .rows
            .iter_mut()
            .find(|r| r.phase() == "reserved")
            .unwrap();
        let CommonContextSignerAuditV1::Reserved {
            read_admission_digest,
            ..
        } = row
        else {
            unreachable!()
        };
        *read_admission_digest = digest;
        assert!(changed.validate(&evidence.request.account_id).is_err());
    }
}

#[test]
fn present_read_must_match_authority_reserve_even_when_local_success_is_missing() {
    let (inventory, evidence) = fixture::fixture();
    let mut only_read = inventory;
    only_read.rows.retain(|r| r.phase() == "read_admitted");
    only_read
        .validate_against(&evidence.complete_history.construction)
        .unwrap();
    for field in 0..4 {
        let mut changed = only_read.clone();
        let CommonContextSignerAuditV1::ReadAdmitted { evidence: read, .. } = &mut changed.rows[0]
        else {
            unreachable!()
        };
        match field {
            0 => read.current_attempt_digest = "bc".repeat(32),
            1 => read.current_attempt_sequence += 1,
            2 => read.request.current_caller_binding_digest = "cd".repeat(32),
            _ => read.writer_session_expires_at_ms += 1,
        }
        // Structurally valid standalone read data cannot be rebound to another
        // authenticated continuing attempt simply by omitting local success.
        changed.validate(&evidence.request.account_id).unwrap();
        assert!(
            changed
                .validate_against(&evidence.complete_history.construction)
                .is_err()
        );
    }
}
