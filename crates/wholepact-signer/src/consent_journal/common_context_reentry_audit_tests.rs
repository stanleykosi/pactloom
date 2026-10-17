//! Inert archival boundary tests. These do not qualify a native handoff,
//! authenticated socket, provider read, restored capability, or publication.
use super::common_context_audit_tests::fixture;
use super::common_context_reentry_audit_fixture as handoff_fixture;
use super::*;
use crate::authority_bridge::host_recovery_ipc::{v4::HostRecoveryContinuityEvidenceV4, v5::*};
use wholepact_authority::construction_transport_handoff_v1::*;

fn legacy_in_v5() -> (
    HostRecoveryContinuityEvidenceV4,
    HostRecoveryContinuityEvidenceV5,
) {
    let (old, v4) = fixture::fixture();
    let v5 = HostRecoveryContinuityEvidenceV5 {
        request: HostRecoveryContinuityRequestV5 {
            schema_version: 5,
            inventory_digest: v4.request.inventory_digest.clone(),
            generation_id: v4.request.generation_id.clone(),
            account_id: v4.request.account_id.clone(),
            network_profile_id: v4.request.network_profile_id.clone(),
            expected_writer_epoch: v4.request.expected_writer_epoch,
            expected_witness: v4.request.expected_witness.clone(),
        },
        writer_certificate_digest: v4.writer_certificate_digest.clone(),
        writer_session_id: Some(v4.writer_session_id.clone()),
        writer_session_expires_at_ms: Some(v4.writer_session_expires_at_ms),
        head: v4.head.clone(),
        history_digest: v4.history_digest.clone(),
        complete_history: HostRecoveryHistoryV5 {
            schema_version: 5,
            financial_origins_v2: v4.complete_history.financial_origins_v2.clone(),
            construction: ConstructionHistoryWithTransportV1 {
                version: 1,
                original: v4.complete_history.construction.clone(),
                transport: ConstructionTransportHistoryV1 {
                    version: 1,
                    grants: vec![],
                    credentials: vec![],
                    reservations: vec![],
                    consumptions: vec![],
                },
            },
            signer_common_context_audit: CommonContextSignerAuditInventoryV2 {
                version: 2,
                original: old,
                reentry: CommonContextReentryAuditInventoryV1 {
                    version: 1,
                    rows: vec![],
                },
            },
        },
    };
    (v4, v5)
}

#[test]
fn explicit_v5_keeps_old_bytes_charge_and_never_issues_recovery() {
    let (old, new) = legacy_in_v5();
    new.validate().unwrap();
    assert!(old.digest().unwrap() != new.digest().unwrap());
    assert_eq!(
        serde_json::to_vec(&old.complete_history.signer_common_context_audit).unwrap(),
        serde_json::to_vec(&new.complete_history.signer_common_context_audit.original).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&old.complete_history.financial_origins_v2).unwrap(),
        serde_json::to_vec(&new.complete_history.financial_origins_v2).unwrap()
    );
    assert_eq!(
        old.complete_history.conservative_debit_zatoshis().unwrap(),
        new.complete_history.conservative_debit_zatoshis().unwrap()
    );
    assert!(new.complete_history.conservative_debit_zatoshis().unwrap() > 0);
    let missing = new.complete_history.missing_local_native_phases().unwrap();
    assert!(missing.legacy.is_empty() && missing.transport.is_empty());
    assert!(
        new.complete_history
            .require_financial_activation_supported()
            .is_err()
    );
    assert!(require_construction_transport_recovery_endpoint().is_err());
    assert!(
        serde_json::from_slice::<HostRecoveryContinuityEvidenceV4>(
            &serde_json::to_vec(&new).unwrap()
        )
        .is_err()
    );
    assert!(
        serde_json::from_slice::<HostRecoveryContinuityEvidenceV5>(
            &serde_json::to_vec(&old).unwrap()
        )
        .is_err()
    );
    let mut downgrade = new.clone();
    downgrade.request.schema_version = 4;
    assert!(downgrade.validate().is_err());
    let mut changed = serde_json::to_value(&new).unwrap();
    changed["restore_owner"] = true.into();
    assert!(serde_json::from_value::<HostRecoveryContinuityEvidenceV5>(changed).is_err());
}

#[test]
fn v5_legacy_projection_preserves_missing_receipts_and_exact_old_caller_join() {
    let (_, evidence) = legacy_in_v5();
    let baseline = evidence
        .complete_history
        .conservative_debit_zatoshis()
        .unwrap();
    for retained in [
        vec![],
        vec!["read_admitted"],
        vec!["read_admitted", "reserved"],
    ] {
        let mut value = evidence.clone();
        value
            .complete_history
            .signer_common_context_audit
            .original
            .rows
            .retain(|r| retained.contains(&r.phase()));
        value.validate().unwrap();
        let missing = value
            .complete_history
            .missing_local_native_phases()
            .unwrap();
        assert_eq!(missing.legacy.len(), 1);
        assert!(missing.legacy[0].missing_consumed);
        assert!(missing.transport.is_empty());
        assert_eq!(
            value
                .complete_history
                .conservative_debit_zatoshis()
                .unwrap(),
            baseline
        );
    }
    let mut value = evidence.clone();
    let row = value
        .complete_history
        .signer_common_context_audit
        .original
        .rows
        .iter_mut()
        .find(|r| r.phase() == "read_admitted")
        .unwrap();
    let CommonContextSignerAuditV1::ReadAdmitted { evidence: read, .. } = row else {
        unreachable!()
    };
    read.request.current_caller_binding_digest = "e9".repeat(32);
    assert!(value.validate().is_err());
    let mut value = evidence;
    value
        .complete_history
        .signer_common_context_audit
        .reentry
        .version = 2;
    assert!(value.validate().is_err());
}

#[test]
fn unauthenticated_authorization_cannot_be_an_audit_predecessor() {
    let (old, _) = fixture::fixture();
    let read_row = old
        .rows
        .iter()
        .find(|r| r.phase() == "read_admitted")
        .unwrap()
        .clone();
    let CommonContextSignerAuditV1::ReadAdmitted {
        evidence: read,
        witness_history: h,
        ..
    } = &read_row
    else {
        unreachable!()
    };
    let snapshot = h.observed_snapshot();
    let genesis = h
        .original_birth()
        .unwrap()
        .request
        .policy
        .account_use_genesis
        .as_ref()
        .unwrap();
    let authorization = SignedConstructionTransportPreauthorizationV1 {
        authorization: ConstructionTransportPreauthorizationV1 {
            version: 1,
            operation_id: "modeled-invalid-reentry-authorization".into(),
            account_id: snapshot.account_id.clone(),
            network_profile_id: snapshot.network_profile_id.clone(),
            genesis_digest: genesis.digest().unwrap(),
            policy_digest: snapshot.policy_digest.clone(),
            original_session: snapshot.active_writer_session.as_ref().unwrap().clone(),
            attempt_digest: read.current_attempt_digest.clone(),
            attempt_sequence: read.current_attempt_sequence,
            read_request_digest: read.request.digest().unwrap(),
            read_evidence_digest: read.digest().unwrap(),
            plan_approval_digest: read.request.witness_plan_approval_digest.clone(),
            invocation_digest: read.request.plan.invocation_digest().unwrap(),
            original_caller_binding_digest: read.request.current_caller_binding_digest.clone(),
            original_host_process_commitment: "c1".repeat(32),
            original_native_binding_digest: "c2".repeat(32),
            native_review_digest: "c3".repeat(32),
            nonce: "c4".repeat(32),
            authorized_at_ms: read.admitted_at_ms,
            expires_at_ms: read
                .request
                .completion_expires_at_ms
                .min(read.writer_session_expires_at_ms),
        },
        scheme: "ecdsa-p256-sha256-asn1-v1".into(),
        owner_certificate_der: vec![1],
        signature: vec![],
    };
    let row = CommonContextReentrySignerAuditV1 {
        version: 1,
        account_id: snapshot.account_id.clone(),
        invocation_digest: read.request.plan.invocation_digest().unwrap(),
        original_read_admission_digest: read.digest().unwrap(),
        record: CommonContextReentryAuditPhaseV1::Authorized {
            authorization: Box::new(authorization),
        },
    };
    row.validate_shape().unwrap();
    let account = snapshot.account_id.clone();
    let inventory = CommonContextSignerAuditInventoryV2 {
        version: 2,
        original: CommonContextSignerAuditInventoryV1 {
            version: 1,
            rows: vec![read_row],
        },
        reentry: CommonContextReentryAuditInventoryV1 {
            version: 1,
            rows: vec![row],
        },
    };
    assert!(inventory.validate(&account).is_err());
}

#[test]
fn signed_handoff_six_phases_fit_original_caps_and_retain_exact_charge() {
    let value = handoff_fixture::fixture();
    let h = &value.complete_history;
    let audit = &h.signer_common_context_audit;
    assert_eq!(audit.original.rows.len(), 1);
    assert_eq!(audit.reentry.rows.len(), 6);
    assert_eq!(h.conservative_debit_zatoshis().unwrap(), 400_012_000);
    assert_eq!(h.construction.transport.reservations.len(), 1);
    assert_eq!(h.construction.transport.consumptions.len(), 1);
    assert!(serde_json::to_vec(h).unwrap().len() <= MAX_COMPLETE_HISTORY_V5_BYTES);
    for row in &audit.reentry.rows {
        assert!(serde_json::to_vec(row).unwrap().len() <= MAX_RECORD_BYTES);
    }
    eprintln!(
        "synthetic-handoff encoded bytes: complete={}, evidence={}, audit={}, phases={:?}",
        serde_json::to_vec(h).unwrap().len(),
        serde_json::to_vec(&value).unwrap().len(),
        serde_json::to_vec(audit).unwrap().len(),
        audit
            .reentry
            .rows
            .iter()
            .map(|r| (r.phase(), serde_json::to_vec(r).unwrap().len()))
            .collect::<Vec<_>>(),
    );
    let round: HostRecoveryContinuityEvidenceV5 =
        serde_json::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(round.digest().unwrap(), value.digest().unwrap());
    let missing = h.missing_local_native_phases().unwrap();
    assert!(missing.legacy.is_empty() && missing.transport.is_empty());
    assert!(h.require_financial_activation_supported().is_err());
    assert!(h.construction.original.validate().is_err());
    assert!(
        serde_json::from_slice::<HostRecoveryContinuityEvidenceV4>(
            &serde_json::to_vec(&value).unwrap()
        )
        .is_err()
    );
    assert_eq!(MAX_RECORD_BYTES, 512 * 1024);
    assert_eq!(MAX_COMPLETE_HISTORY_V5_BYTES, 1024 * 1024 - 4096);
    assert_eq!(MAX_BACKUP_ENCODED_BYTES, 64 * 1024 * 1024);
}

#[test]
fn signed_handoff_each_missing_local_suffix_stays_charged_and_orphans_fail() {
    let value = handoff_fixture::fixture();
    let phases = [
        "authorized",
        "granted",
        "claimed",
        "reentered",
        "reserved",
        "consumed",
    ];
    for retained in 0..phases.len() {
        let mut changed = value.clone();
        changed
            .complete_history
            .signer_common_context_audit
            .reentry
            .rows
            .retain(|r| phases[..retained].contains(&r.phase()));
        changed.validate().unwrap();
        let missing = changed
            .complete_history
            .missing_local_native_phases()
            .unwrap();
        assert!(missing.legacy.is_empty());
        assert_eq!(missing.transport.len(), 1);
        let m = &missing.transport[0];
        assert_eq!(m.missing_authorized, retained < 1);
        assert_eq!(m.missing_granted, retained < 2);
        assert_eq!(m.missing_claimed, retained < 3);
        assert_eq!(m.missing_reentered, retained < 4);
        assert_eq!(m.missing_reserved, retained < 5);
        assert!(m.missing_consumed);
        assert!(!m.missing_read_admission);
        assert_eq!(
            changed
                .complete_history
                .conservative_debit_zatoshis()
                .unwrap(),
            400_012_000
        );
    }
    let mut absent = value.clone();
    absent
        .complete_history
        .signer_common_context_audit
        .original
        .rows
        .clear();
    absent
        .complete_history
        .signer_common_context_audit
        .reentry
        .rows
        .clear();
    absent.validate().unwrap();
    let missing = absent
        .complete_history
        .missing_local_native_phases()
        .unwrap();
    assert!(missing.transport[0].missing_read_admission);
    assert_eq!(
        absent
            .complete_history
            .conservative_debit_zatoshis()
            .unwrap(),
        400_012_000
    );
    for phase in &phases[..5] {
        let mut orphan = value.clone();
        orphan
            .complete_history
            .signer_common_context_audit
            .reentry
            .rows
            .retain(|r| r.phase() != *phase);
        assert!(orphan.validate().is_err(), "missing predecessor {phase}");
    }
    let mut orphan = value;
    orphan
        .complete_history
        .signer_common_context_audit
        .original
        .rows
        .clear();
    assert!(orphan.validate().is_err());
}

#[test]
fn signed_handoff_exact_lineage_substitutions_fail_after_complete_validation() {
    let value = handoff_fixture::fixture();
    for field in 0..16 {
        let mut changed = value.clone();
        let row = changed
            .complete_history
            .signer_common_context_audit
            .reentry
            .rows
            .iter_mut()
            .find(|r| r.phase() == "reentered")
            .unwrap();
        let CommonContextReentryAuditPhaseV1::Reentered {
            lineage,
            witness_history,
        } = &mut row.record
        else {
            unreachable!()
        };
        let h = "e9".repeat(32);
        match field {
            0 => lineage.request.pending_grant_digest = h,
            1 => lineage.original_host_process_digest = h,
            2 => lineage.original_native_binding_digest = h,
            3 => lineage.current_native_binding_digest = h,
            4 => lineage.original_record_digest = h,
            5 => lineage.original_genesis_digest = h,
            6 => lineage.original_birth_digest = h,
            7 => lineage.current_witness_history_digest = h,
            8 => lineage.current_writer_session_digest = h,
            9 => lineage.construction_transport_credential_digest = h,
            10 => lineage.construction_transport_credential_id = h,
            11 => lineage.original_transport_fence_digest = h,
            12 => lineage.native_review_digest = h,
            13 => lineage.request.requested_at_ms = 253_009,
            14 => lineage.request.admission_expires_at_ms += 1,
            _ => witness_history.transport.credentials.clear(),
        }
        assert!(changed.validate().is_err(), "substitution {field}");
    }
    for phase in ["authorized", "claimed"] {
        let mut changed = value.clone();
        let row = changed
            .complete_history
            .signer_common_context_audit
            .reentry
            .rows
            .iter_mut()
            .find(|r| r.phase() == phase)
            .unwrap();
        match &mut row.record {
            CommonContextReentryAuditPhaseV1::Authorized { authorization } => {
                authorization.signature[0] ^= 1
            }
            CommonContextReentryAuditPhaseV1::Claimed { credential } => {
                credential.signed_claim.signature[0] ^= 1
            }
            _ => unreachable!(),
        }
        assert!(changed.validate().is_err());
    }
    let mut missing_remote = value;
    missing_remote
        .complete_history
        .construction
        .transport
        .grants
        .clear();
    assert!(missing_remote.validate().is_err());
}

#[test]
fn signed_handoff_encoded_overflow_refuses_without_dropping_complete_facts() {
    let value = handoff_fixture::fixture();
    let mut audit = value.complete_history.signer_common_context_audit.clone();
    let repeated = audit
        .reentry
        .rows
        .iter()
        .find(|r| r.phase() == "reentered")
        .unwrap()
        .clone();
    // All copied rows retain their complete signed facts. The encoder bound
    // must refuse before duplicate/cardinality validation can hide the limit.
    while serde_json::to_vec(&audit).unwrap().len() <= MAX_COMPLETE_HISTORY_V5_BYTES {
        audit.reentry.rows.push(repeated.clone());
    }
    assert!(audit.reentry.rows.len() < common_context_reentry_audit_v1::MAX_REENTRY_AUDIT_ROWS);
    assert!(matches!(
        audit.validate(&value.request.account_id),
        Err(JournalError::Limit)
    ));
    let mut row = repeated;
    loop {
        if serde_json::to_vec(&row).unwrap().len() > MAX_RECORD_BYTES {
            break;
        }
        let CommonContextReentryAuditPhaseV1::Reentered {
            witness_history, ..
        } = &mut row.record
        else {
            unreachable!()
        };
        witness_history
            .transport
            .credentials
            .push(witness_history.transport.credentials[0].clone());
    }
    assert!(matches!(row.validate_shape(), Err(JournalError::Limit)));
    let mut overflow = value.complete_history;
    let mut reservation = overflow.construction.transport.reservations[0].clone();
    reservation.original.reserved_debit_zatoshis = u64::MAX;
    overflow
        .construction
        .transport
        .reservations
        .push(reservation);
    assert!(overflow.conservative_debit_zatoshis().is_err());
}

#[test]
fn signed_handoff_encrypted_six_phase_reopen_is_exact_and_atomic() {
    use std::collections::{BTreeMap, BTreeSet};
    use wholepact_storage_security::{DatabaseKey, bundle::*};
    let value = handoff_fixture::fixture();
    let account = &value.request.account_id;
    let audit = &value.complete_history.signer_common_context_audit;
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("never-funded-handoff-journal.sqlite");
    let key = DatabaseKey::from_bytes([81; 32]);
    let mut journal =
        SignerConsentJournal::create_encrypted(&path, &key, account, 1, false).unwrap();
    journal
        .retain_common_context_audit_v3(&audit.original.rows[0])
        .unwrap();
    for phase in [
        "authorized",
        "granted",
        "claimed",
        "reentered",
        "reserved",
        "consumed",
    ] {
        let row = audit
            .reentry
            .rows
            .iter()
            .find(|r| r.phase() == phase)
            .unwrap();
        let before = storage::capacity_estimate(&journal.connection.lock().unwrap()).unwrap();
        journal.capacity_limits = (MAX_BACKUP_ROWS, before.1);
        assert!(journal.retain_common_context_reentry_audit_v1(row).is_err());
        assert_eq!(
            before,
            storage::capacity_estimate(&journal.connection.lock().unwrap()).unwrap()
        );
        journal.capacity_limits = (MAX_BACKUP_ROWS, MAX_BACKUP_ENCODED_BYTES);
        journal.retain_common_context_reentry_audit_v1(row).unwrap();
        assert!(journal.retain_common_context_reentry_audit_v1(row).is_err());
    }
    let bytes = serde_json::to_vec(audit).unwrap();
    {
        let c = journal.connection.lock().unwrap();
        storage::verify_schema(&c).unwrap();
        assert_eq!(
            serde_json::to_vec(
                &common_context_reentry_audit_v1::read_complete(&c, account).unwrap()
            )
            .unwrap(),
            bytes
        );
        assert!(storage::require_no_unimplemented_reentry(&c).is_err());
        for sql in [
            "DELETE FROM signer_common_context_reentry_v1",
            "UPDATE signer_common_context_reentry_v1 SET phase='authorized'",
        ] {
            assert!(c.execute(sql, []).is_err());
        }
    }
    drop(journal);
    let journal = SignerConsentJournal::open_encrypted(&path, &key, account).unwrap();
    assert_eq!(
        serde_json::to_vec(
            &common_context_reentry_audit_v1::read_complete(
                &journal.connection.lock().unwrap(),
                account
            )
            .unwrap()
        )
        .unwrap(),
        bytes
    );
    let CommonContextReentryAuditPhaseV1::Reserved {
        extension,
        continuation,
        record,
        ..
    } = &audit
        .reentry
        .rows
        .iter()
        .find(|r| r.phase() == "reserved")
        .unwrap()
        .record
    else {
        unreachable!()
    };
    let CommonContextSignerAuditV1::ReadAdmitted {
        evidence: original_read,
        ..
    } = &audit.original.rows[0]
    else {
        unreachable!()
    };
    let mut legacy_record = record.original.clone();
    legacy_record
        .request
        .construction
        .current_caller_binding_digest =
        original_read.request.current_caller_binding_digest.clone();
    let mixed = CommonContextSignerAuditV1::Reserved {
        version: 1,
        read_admission_digest: audit.reentry.rows[0].original_read_admission_digest.clone(),
        extension: extension.clone(),
        continuation: continuation.clone(),
        record: Box::new(legacy_record),
    };
    let mut legacy_rows = vec![audit.original.rows[0].clone(), mixed.clone()];
    legacy_rows.sort_by_key(|r| (r.invocation_digest().unwrap(), r.phase()));
    CommonContextSignerAuditInventoryV1 {
        version: 1,
        rows: legacy_rows,
    }
    .validate(account)
    .unwrap();
    let before = storage::capacity_estimate(&journal.connection.lock().unwrap()).unwrap();
    assert!(journal.retain_common_context_audit_v3(&mixed).is_err());
    assert_eq!(
        before,
        storage::capacity_estimate(&journal.connection.lock().unwrap()).unwrap()
    );
    let archive = dir.path().join("never-funded-handoff-archive.sqlite");
    let restored = dir.path().join("quarantined-handoff.sqlite");
    let archive_key = DatabaseKey::from_bytes([82; 32]);
    let restored_key = DatabaseKey::from_bytes([83; 32]);
    let adapter = journal.backup_adapter();
    let sources = [RegisteredJournal::new("signer-authority", &adapter).unwrap()];
    snapshot(SnapshotRequest {
        principal_id: "synthetic-owner",
        profile_id: "synthetic-signer-profile",
        coverage: Coverage {
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
        },
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
    assert!(SignerConsentJournal::open_encrypted(&restored, &restored_key, account).is_err());
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
    assert_eq!(source.provenance().schema_version, SCHEMA_VERSION);
    let table = source
        .tables()
        .iter()
        .find(|t| t.name() == "signer_common_context_reentry_v1")
        .unwrap();
    assert_eq!(table.rows().len(), 6);
    let mut restored_rows: Vec<CommonContextReentrySignerAuditV1> = table
        .rows()
        .iter()
        .map(|r| {
            let wholepact_storage_security::bundle::recovery::RecoveryCell::Text(payload) =
                &r.cells()[4]
            else {
                panic!("exact text payload")
            };
            serde_json::from_str(payload).unwrap()
        })
        .collect();
    restored_rows.sort_by_key(|r| (r.invocation_digest.clone(), r.phase()));
    assert_eq!(
        serde_json::to_vec(&restored_rows).unwrap(),
        serde_json::to_vec(&audit.reentry.rows).unwrap()
    );
    let restored_audit = CommonContextSignerAuditInventoryV2 {
        version: 2,
        original: audit.original.clone(),
        reentry: CommonContextReentryAuditInventoryV1 {
            version: 1,
            rows: restored_rows,
        },
    };
    restored_audit
        .validate_against(&value.complete_history.construction)
        .unwrap();
}

#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
#[test]
fn signed_handoff_reopen_requires_exact_authorized_only_original_journal() {
    use wholepact_storage_security::DatabaseKey;
    let value = handoff_fixture::fixture();
    let audit = &value.complete_history.signer_common_context_audit;
    let genesis = value
        .complete_history
        .financial_origins_v2
        .account_use
        .genesis
        .as_ref()
        .unwrap();
    let account = &genesis.identity.account_id;
    let dir = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = DatabaseKey::from_bytes([84; 32]);
    let journal = SignerConsentJournal::create_encrypted(
        &dir.path().join("never-funded-authorized-only.sqlite"),
        &key,
        account,
        1,
        false,
    )
    .unwrap();
    journal
        .connection
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
            rusqlite::params![
                account,
                genesis.identity.full_viewing_key_digest,
                genesis.digest().unwrap(),
                encode(genesis).unwrap().as_str()
            ],
        )
        .unwrap();
    let CommonContextSignerAuditV1::ReadAdmitted { evidence: read, .. } = &audit.original.rows[0]
    else {
        unreachable!()
    };
    let authorization = audit
        .reentry
        .rows
        .iter()
        .find(|r| r.phase() == "authorized")
        .unwrap();
    let CommonContextReentryAuditPhaseV1::Authorized {
        authorization: signed,
    } = &authorization.record
    else {
        unreachable!()
    };
    journal
        .retain_common_context_audit_v3(&audit.original.rows[0])
        .unwrap();
    let check = |strict| {
        journal.check_common_context_authorized_reentry_owner(
            &CommonContextAuthorizedReentryOwnerInput {
                genesis,
                epoch: 1,
                read_digest: &read.digest().unwrap(),
                attempt_digest: &read.current_attempt_digest,
                attempt_sequence: read.current_attempt_sequence,
                plan: &read.request.plan,
                authorization_digest: &signed.digest().unwrap(),
            },
            strict,
        )
    };
    assert!(check(true).is_err());
    journal
        .retain_common_context_reentry_audit_v1(authorization)
        .unwrap();
    check(true).unwrap();
    assert!(
        journal
            .check_common_context_authorized_reentry_owner(
                &CommonContextAuthorizedReentryOwnerInput {
                    genesis,
                    epoch: 1,
                    read_digest: &"ef".repeat(32),
                    attempt_digest: &read.current_attempt_digest,
                    attempt_sequence: read.current_attempt_sequence,
                    plan: &read.request.plan,
                    authorization_digest: &signed.digest().unwrap(),
                },
                true,
            )
            .is_err()
    );
    assert!(
        journal
            .check_common_context_authorized_reentry_owner(
                &CommonContextAuthorizedReentryOwnerInput {
                    genesis,
                    epoch: 2,
                    read_digest: &read.digest().unwrap(),
                    attempt_digest: &read.current_attempt_digest,
                    attempt_sequence: read.current_attempt_sequence,
                    plan: &read.request.plan,
                    authorization_digest: &signed.digest().unwrap(),
                },
                true,
            )
            .is_err()
    );
    journal
        .retain_common_context_reentry_audit_v1(
            audit
                .reentry
                .rows
                .iter()
                .find(|r| r.phase() == "granted")
                .unwrap(),
        )
        .unwrap();
    assert!(check(true).is_err());
    check(false).unwrap();
}


/// Real encrypted storage with inert signed archival facts. No native owner,
/// callback, socket, financial authority or currentness proof is manufactured.
#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
fn with_owner_snapshot_fixture(test: impl FnOnce(&SignerConsentJournal, &HostRecoveryContinuityEvidenceV5)) {
    use std::os::unix::fs::PermissionsExt;
    use wholepact_storage_security::DatabaseKey;
    let value = handoff_fixture::fixture();
    let audit = &value.complete_history.signer_common_context_audit;
    let genesis = value.complete_history.financial_origins_v2.account_use.genesis.as_ref().unwrap();
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let journal = SignerConsentJournal::create_encrypted(
        &dir.path().join("never-funded-snapshot.sqlite"),
        &DatabaseKey::from_bytes([85; 32]),
        &genesis.identity.account_id,
        1,
        false,
    ).unwrap();
    journal.connection.lock().unwrap().execute(
        "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
        rusqlite::params![
            genesis.identity.account_id,
            genesis.identity.full_viewing_key_digest,
            genesis.digest().unwrap(),
            encode(genesis).unwrap().as_str()
        ],
    ).unwrap();
    journal.retain_common_context_audit_v3(&audit.original.rows[0]).unwrap();
    journal.retain_common_context_reentry_audit_v1(
        audit.reentry.rows.iter().find(|r| r.phase() == "authorized").unwrap(),
    ).unwrap();
    test(&journal, &value);
}

#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
fn check_owner_snapshot(journal: &SignerConsentJournal, value: &HostRecoveryContinuityEvidenceV5) -> Result<CommonContextSignerAuditV1> {
    let audit = &value.complete_history.signer_common_context_audit;
    let CommonContextSignerAuditV1::ReadAdmitted { evidence, .. } = &audit.original.rows[0] else { unreachable!() };
    let authorization = audit.reentry.rows.iter().find_map(|row| match &row.record {
        CommonContextReentryAuditPhaseV1::Authorized { authorization } => Some(authorization),
        _ => None,
    }).unwrap();
    journal.check_common_context_authorized_reentry_owner(
        &CommonContextAuthorizedReentryOwnerInput {
            genesis: value.complete_history.financial_origins_v2.account_use.genesis.as_ref().unwrap(),
            epoch: 1,
            read_digest: &evidence.digest().unwrap(),
            attempt_digest: &evidence.current_attempt_digest,
            attempt_sequence: evidence.current_attempt_sequence,
            plan: &evidence.request.plan,
            authorization_digest: &authorization.digest().unwrap(),
        },
        true,
    )
}

#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
#[test]
fn owner_snapshot_is_fresh_and_never_commits_a_callers_transaction() {
    with_owner_snapshot_fixture(|journal, value| {
        let expected = &value.complete_history.signer_common_context_audit.original.rows[0];
        assert!(check_owner_snapshot(journal, value).unwrap() == *expected);
        assert!(journal.connection.lock().unwrap().is_autocommit());
        // The exact same connection has an explicit outer transaction: refuse
        // without adopting, rolling back or committing the caller's work.
        journal.connection.lock().unwrap().execute_batch("BEGIN DEFERRED").unwrap();
        assert!(check_owner_snapshot(journal, value).is_err());
        {
            let c = journal.connection.lock().unwrap();
            assert!(!c.is_autocommit());
            c.execute_batch("ROLLBACK").unwrap();
        }
        assert!(check_owner_snapshot(journal, value).unwrap() == *expected);
        // Every call freshly rechecks mutable account state; no successful
        // inventory/transaction is reused after it returns.
        journal.connection.lock().unwrap().execute("UPDATE signer_account SET recovery_required=1", []).unwrap();
        assert!(check_owner_snapshot(journal, value).is_err());
        assert!(journal.connection.lock().unwrap().is_autocommit());
        journal.connection.lock().unwrap().execute("UPDATE signer_account SET recovery_required=0", []).unwrap();
        assert!(check_owner_snapshot(journal, value).unwrap() == *expected);
        journal.connection.lock().unwrap().execute_batch("CREATE TABLE foreign_snapshot_row(value TEXT)").unwrap();
        assert!(check_owner_snapshot(journal, value).is_err());
        assert!(journal.connection.lock().unwrap().is_autocommit());
        journal.connection.lock().unwrap().execute_batch("DROP TABLE foreign_snapshot_row").unwrap();
        assert!(check_owner_snapshot(journal, value).unwrap() == *expected);
        // A row in an otherwise valid non-construction table still violates
        // this exact original-owner inventory policy, independently of schema.
        {
            let c = journal.connection.lock().unwrap();
            c.execute(
                "INSERT INTO signer_enrollments VALUES('inert-ref',?1,'inert-agreement','inert-participant','{}')",
                [&value.request.account_id],
            ).unwrap();
            storage::verify_schema(&c).unwrap();
        }
        assert!(check_owner_snapshot(journal, value).is_err());
        assert!(journal.connection.lock().unwrap().is_autocommit());
    });
}

#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
#[test]
fn owner_snapshot_revalidates_changed_payload_and_missing_rows() {
    with_owner_snapshot_fixture(|journal, value| {
        check_owner_snapshot(journal, value).unwrap();
        // Adversarial encrypted storage edits restore the exact original schema
        // before each check. The refusal must therefore inspect actual rows,
        // not only schema, a cached result or a file timestamp.
        let (trigger, payload): (String, String) = {
            let c = journal.connection.lock().unwrap();
            (
                c.query_row("SELECT sql FROM sqlite_schema WHERE name='signer_common_context_reentry_no_update'", [], |r| r.get(0)).unwrap(),
                c.query_row("SELECT payload FROM signer_common_context_reentry_v1 WHERE phase='authorized'", [], |r| r.get(0)).unwrap(),
            )
        };
        for replacement in ["{}", payload.as_str()] {
            {
                let c = journal.connection.lock().unwrap();
                c.execute_batch("DROP TRIGGER signer_common_context_reentry_no_update").unwrap();
                c.execute("UPDATE signer_common_context_reentry_v1 SET payload=?1 WHERE phase='authorized'", [replacement]).unwrap();
                c.execute_batch(&trigger).unwrap();
            }
            assert_eq!(check_owner_snapshot(journal, value).is_ok(), replacement == payload);
            assert!(journal.connection.lock().unwrap().is_autocommit());
        }
        {
            let c = journal.connection.lock().unwrap();
            let trigger: String = c.query_row("SELECT sql FROM sqlite_schema WHERE name='signer_common_context_reentry_no_delete'", [], |r| r.get(0)).unwrap();
            c.execute_batch("DROP TRIGGER signer_common_context_reentry_no_delete").unwrap();
            c.execute("DELETE FROM signer_common_context_reentry_v1", []).unwrap();
            c.execute_batch(&trigger).unwrap();
        }
        assert!(check_owner_snapshot(journal, value).is_err());
        assert!(journal.connection.lock().unwrap().is_autocommit());
    });
}

#[test]
fn completed_shape_pass_still_rejects_lineage_history_and_reservation_tampering() {
    let value = handoff_fixture::fixture();
    let audit = &value.complete_history.signer_common_context_audit;
    let account = &value.request.account_id;
    audit.validate(account).unwrap();
    for field in 0..3 {
        let mut altered = audit.clone();
        if field < 2 {
            let row = altered.reentry.rows.iter_mut().find(|r| r.phase() == "reentered").unwrap();
            let CommonContextReentryAuditPhaseV1::Reentered { lineage, witness_history } = &mut row.record else { unreachable!() };
            if field == 0 { lineage.version = 0; } else { witness_history.version = 0; }
        } else {
            let row = altered.reentry.rows.iter_mut().find(|r| r.phase() == "reserved").unwrap();
            let CommonContextReentryAuditPhaseV1::Reserved { record, .. } = &mut row.record else { unreachable!() };
            record.original.request.version = 0;
        }
        assert!(altered.validate(account).is_err());
    }
}
