//! Isolated synthetic consent/database fixtures. No spending key, proof, socket,
//! node, real application identity or financial execution is involved.
use super::*;
use crate::consent_journal::authority::fixture;
use sha2::Digest;
use wholepact_core::{Amount, Proposal, automation::*};
use wholepact_storage_security::DatabaseKey;

fn amount(n: u64) -> Amount {
    Amount::from_zatoshis(n).unwrap()
}
struct Fixture {
    private_directory: crate::files::PrivateDirectory,
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    key: DatabaseKey,
    journal: SignerConsentJournal,
    session: SignerConsentSession,
    enrollment: AccountEnrollmentRecord,
    manifest: AcceptedManifestRecord,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = dir.path().join("synthetic-automation-journal");
        let key = DatabaseKey::from_bytes([42; 32]);
        let private_directory = crate::files::PrivateDirectory::open(dir.path()).unwrap();
        let journal = SignerConsentJournal::create_encrypted(
            &path,
            &key,
            "account-alice",
            1,
            false,
            &private_directory
                .signer_journal_source_owner_for_test(&path)
                .unwrap(),
        )
        .unwrap();
        let session = fixture::session(&journal, "synthetic-owner");
        let mut input =
            crate::consent_journal::tests::proposal("agreement-a", "obligation-a", "proposal-a")
                .input()
                .clone();
        input.manifest.agreement.network_profile_id = AUTOMATION_PROFILE.into();
        input.artifact_digest = Some(hex::encode(sha2::Sha256::digest(
            b"synthetic-automatic-storage-artifact",
        )));
        let proposal = Proposal::validate(input).unwrap();
        let enrollment = journal
            .record_enrollment(fixture::approve_enrollment(
                &session,
                EnrollmentTerms {
                    account_id: "account-alice".into(),
                    agreement_id: "agreement-a".into(),
                    participant_id: "alice".into(),
                    principal_id: "synthetic-owner".into(),
                    network_profile_id: AUTOMATION_PROFILE.into(),
                    privacy_domain: "synthetic-domain".into(),
                    account_fvk_digest: "fa".repeat(32),
                    transport: TransportIdentityBinding::LocalProcess {
                        transport_identity_id: "synthetic-selected-app".into(),
                        channel_key_digest: "a1".repeat(32),
                        channel_binding_digest: "a2".repeat(32),
                        uid: 1000,
                        pid: 123,
                        process_instance: "a3".repeat(32),
                        signer_generation: 1,
                        account_id: "account-alice".into(),
                        agreement_id: "agreement-a".into(),
                        participant_id: "alice".into(),
                        manifest_digest: proposal.manifest_digest().into(),
                    },
                    aggregate_budget_limit_zatoshis: 1_000_000_000,
                    receipt: fixture::receipt(&session),
                },
            ))
            .unwrap();
        let p = session.prepare_manifest(&enrollment, &proposal).unwrap();
        let decision = fixture::decision(&session, p.review_digest());
        let manifest = journal
            .record_accepted_manifest(session.approve_manifest(p, decision).unwrap())
            .unwrap();
        Self {
            private_directory,
            _dir: dir,
            path,
            key,
            journal,
            session,
            enrollment,
            manifest,
        }
    }
    fn prepared(&self) -> PreparedAutomationGrantChange {
        let now = now_ms().unwrap();
        let policy = AutomationAccountPolicy {
            policy_id: "synthetic-account-policy".into(),
            account_id: "account-alice".into(),
            writer_epoch: 1,
            maximum_outstanding_debit: amount(1_000_000_000),
            valid_from_ms: now - 1000,
            expires_at_ms: now + 300_000,
        };
        let terms = AutomationGrantTerms {
            grant_id: "synthetic-grant".into(),
            application_id: "synthetic-selected-app".into(),
            account_id: "account-alice".into(),
            account_policy_id: policy.policy_id.clone(),
            writer_epoch: 1,
            network_profile: AUTOMATION_PROFILE.into(),
            signer_id: "synthetic-signer".into(),
            verifier_id: "native-exact-automation-v1".into(),
            agreement_ids: vec!["agreement-a".into()],
            recipient_fingerprints: vec!["a4".repeat(32)],
            maximum_payment_debit: amount(500_000_000),
            maximum_payment_fee: amount(30_000),
            maximum_outstanding_debit: amount(500_000_000),
            evidence: [
                AutomationEvidenceKind::AccountControl,
                AutomationEvidenceKind::RecipientInstructions,
                AutomationEvidenceKind::ExactEffects,
                AutomationEvidenceKind::CurrentChain,
                AutomationEvidenceKind::ExposureContinuity,
            ]
            .into_iter()
            .map(|kind| AutomationEvidenceRequirement {
                kind,
                verifier_id: "native-exact-automation-v1".into(),
                maximum_age_ms: 120_000,
            })
            .collect(),
            maximum_authorization_lifetime_ms: 60_000,
            maximum_expiry_height_delta: 200,
            valid_from_ms: policy.valid_from_ms,
            expires_at_ms: policy.expires_at_ms,
        };
        self.session
            .prepare_automation_grant(
                &self.journal,
                &self.enrollment,
                policy,
                terms,
                SponsorWitnessBinding {
                    witness_id: "synthetic-witness".into(),
                    policy_digest: "a5".repeat(32),
                    aggregate_budget_zatoshis: 1_000_000_000,
                },
                AutomationGrantStatus::Active,
            )
            .unwrap()
    }
    fn commit(&self, prepared: PreparedAutomationGrantChange) -> NativeAutomationGrantRecord {
        let decision = fixture::decision(&self.session, prepared.review_digest());
        self.journal
            .record_automation_grant(
                self.session
                    .approve_automation_grant(prepared, decision)
                    .unwrap(),
            )
            .unwrap()
    }
    fn control(
        &self,
        old: &NativeAutomationGrantRecord,
        status: AutomationGrantStatus,
    ) -> NativeAutomationGrantRecord {
        self.commit(
            self.session
                .prepare_automation_grant(
                    &self.journal,
                    &self.enrollment,
                    old.policy.clone(),
                    old.terms.clone(),
                    old.witness.clone(),
                    status,
                )
                .unwrap(),
        )
    }
    fn automatic(&self, grant: &NativeAutomationGrantRecord) -> ApprovedAutomaticSpendConsent {
        let mut terms = crate::consent_journal::tests::terms(
            &self.session,
            &self.enrollment,
            &self.manifest,
            "synthetic-auto-authorization",
        );
        terms.artifact_digest = self
            .manifest
            .proposal_input()
            .artifact_digest
            .clone()
            .unwrap();
        authority::synthetic_automatic_spend(&self.session, terms, grant)
    }
}
#[test]
fn native_automation_revision_pause_renew_revoke_is_immutable() {
    let f = Fixture::new();
    let g = f.commit(f.prepared());
    assert_eq!(g.binding.revision, 1);
    let paused = f.control(&g, AutomationGrantStatus::Paused);
    assert_eq!(paused.binding.revision, 2);
    assert_eq!(paused.binding.terms_digest, g.binding.terms_digest);
    assert!(paused.require_active(now_ms().unwrap()).is_err());
    let renewed = f.control(&paused, AutomationGrantStatus::Active);
    assert_eq!(renewed.binding.revision, 3);
    let revoked = f.control(&renewed, AutomationGrantStatus::Revoked);
    assert_eq!(revoked.binding.revision, 4);
    assert!(
        f.session
            .prepare_automation_grant(
                &f.journal,
                &f.enrollment,
                revoked.policy.clone(),
                revoked.terms.clone(),
                revoked.witness.clone(),
                AutomationGrantStatus::Active
            )
            .is_err()
    );
    let c = f.journal.connection.lock().unwrap();
    assert!(
        c.execute("UPDATE signer_automation_grant_events SET revision=9", [])
            .is_err()
    );
    assert!(
        c.execute("DELETE FROM signer_automation_grant_events", [])
            .is_err()
    );
    assert_eq!(
        c.query_row(
            "SELECT count(*) FROM signer_automation_grant_events",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        4
    );
}
#[test]
fn native_automation_requires_exact_grant_decision_and_selected_application() {
    let f = Fixture::new();
    let p = f.prepared();
    assert!(
        f.session
            .approve_automation_grant(p, fixture::decision(&f.session, &"ff".repeat(32)))
            .is_err()
    );
    let p = f.prepared();
    let mut terms = p.record().terms.clone();
    terms.application_id = "other-application".into();
    assert!(
        f.session
            .prepare_automation_grant(
                &f.journal,
                &f.enrollment,
                p.record().policy.clone(),
                terms,
                p.record().witness.clone(),
                AutomationGrantStatus::Active
            )
            .is_err()
    );
    let p = f.prepared();
    let decision = fixture::decision(&f.session, p.review_digest());
    let approved = f.session.approve_automation_grant(p, decision).unwrap();
    f.session.invalidate().unwrap();
    assert!(f.journal.record_automation_grant(approved).is_err());
}
#[test]
fn automatic_consent_requires_sealed_continuation_and_cannot_masquerade_as_manual() {
    let f = Fixture::new();
    let g = f.commit(f.prepared());
    let approved = f.automatic(&g);
    let exact = approved.record().clone();
    assert!(
        f.journal
            .record_original_consent_release(fixture::exact_spend(&f.session, exact))
            .is_err()
    );
    let (evidence, continuation) = f
        .journal
        .record_automatic_consent_release(approved)
        .unwrap();
    let lease = f
        .journal
        .acquire_original_authorization(
            &evidence.original_consent().terms().authorization_id,
            &f.session,
        )
        .unwrap();
    assert!(lease.require_current_spending_decision().is_err());
    assert!(lease.require_current_authorization().is_err());
    drop(lease);
    let lease = f
        .journal
        .original_automatic_authorization_lease(
            &evidence.original_consent().terms().authorization_id,
            &f.session,
            &continuation,
        )
        .unwrap();
    lease.require_current_authorization().unwrap();
    assert!(lease.require_current_spending_decision().is_err());
    drop(lease);
    f.control(&g, AutomationGrantStatus::Paused);
    assert!(
        f.journal
            .original_automatic_authorization_lease(
                &evidence.original_consent().terms().authorization_id,
                &f.session,
                &continuation
            )
            .is_err()
    );
    assert!(
        f.journal
            .original_authorization(
                &evidence.original_consent().terms().authorization_id,
                &f.session
            )
            .unwrap()
            .is_some()
    );
}
#[test]
fn automation_restart_and_recovery_epoch_do_not_reissue_consent() {
    let f = Fixture::new();
    let g = f.commit(f.prepared());
    let (_, continuation) = f
        .journal
        .record_automatic_consent_release(f.automatic(&g))
        .unwrap();
    let reopened = SignerConsentJournal::open_encrypted(
        &f.path,
        &f.key,
        "account-alice",
        &f.private_directory
            .signer_journal_source_owner_for_test(&f.path)
            .unwrap(),
    )
    .unwrap();
    let session = fixture::session(&reopened, "synthetic-owner");
    assert!(reopened
        .original_automatic_authorization_lease(
            "synthetic-auto-authorization",
            &session,
            &continuation
        )
        .is_err());
    assert_eq!(reopened.automation_grants(&session).unwrap().len(), 1);
    // Synthetic successor epoch models the recovery writer fence. Historical
    // grant rows remain unchanged, but the old epoch can never become eligible.
    reopened
        .connection
        .lock()
        .unwrap()
        .execute("UPDATE signer_account SET writer_epoch=2", [])
        .unwrap();
    let restored = fixture::session(&reopened, "synthetic-owner");
    let historical = reopened
        .automation_grant(&g.binding.grant_id, &restored)
        .unwrap()
        .unwrap();
    assert_eq!(historical.binding, g.binding);
    assert!(
        reopened
            .record_automatic_consent_release(f.automatic(&g))
            .is_err()
    );
    let c = reopened.connection.lock().unwrap();
    let terms = storage::read_original(&c, "synthetic-auto-authorization")
        .unwrap()
        .unwrap();
    assert!(current_for_consent(&c, terms.original_consent().terms()).is_err());
}
#[test]
fn manual_serialization_omits_automation_and_preserves_legacy_reference() {
    let f = Fixture::new();
    let terms = crate::consent_journal::tests::terms(
        &f.session,
        &f.enrollment,
        &f.manifest,
        "synthetic-manual",
    );
    let raw = serde_json::to_value(&terms).unwrap();
    assert!(raw.get("automation").is_none());
    let original = OriginalSpendConsent::new(terms).unwrap();
    assert_eq!(
        original.reference(),
        digest("wholepact:signer-original-spend-consent:v1", &raw).unwrap()
    );
}

#[cfg(feature = "synthetic-qualification")]
#[test]
fn automatic_bridge_requires_exact_opaque_admission_and_retains_once() {
    use crate::authority_bridge::protocol::{
        AuthorizationDeliveryScope, RetainedAuthorizationRequest,
    };
    use wholepact_authority::{
        AccountPolicy, AuthorityJournal, AuthorizeAutomaticKeyUse, OwnerControl,
        OwnerControlRequest, WitnessAutomationAccountPolicy, WitnessAutomationGrant,
        transport::synthetic,
    };
    let f = Fixture::new();
    let template = f.prepared();
    let candidate = template.record();
    let delivery = AuthorizationDeliveryScope {
        candidate_id: "proposal-a".into(),
    };
    let recipient_scope = digest(
        "wholepact:signer-exact-authorization-recipient:v1",
        &(f.enrollment.transport(), &delivery),
    )
    .unwrap();
    let policy = AccountPolicy {
        account_use_genesis: None,
        witness_id: candidate.witness.witness_id.clone(),
        account_id: "account-alice".into(),
        network_profile_id: AUTOMATION_PROFILE.into(),
        owner_certificate_digest: "a1".repeat(32),
        initial_writer_certificate_digest: "b2".repeat(32),
        initial_writer_epoch: 1,
        enrollment_refs: vec![f.enrollment.reference().into()],
        agreement_ids: vec!["agreement-a".into()],
        recipient_scope_digests: vec![recipient_scope.clone()],
        aggregate_budget_zatoshis: 1_000_000_000,
        per_operation_limit_zatoshis: 500_000_000,
        maximum_fee_share_zatoshis: 30_000,
        maximum_transaction_fee_zatoshis: 30_000,
        maximum_permit_lifetime_ms: 120_000,
        policy_expires_at_ms: candidate.terms.expires_at_ms,
    };
    let mut witness_binding = candidate.witness.clone();
    witness_binding.policy_digest = policy.policy_digest().unwrap();
    let grant = f.commit(
        f.session
            .prepare_automation_grant(
                &f.journal,
                &f.enrollment,
                candidate.policy.clone(),
                candidate.terms.clone(),
                witness_binding,
                AutomationGrantStatus::Active,
            )
            .unwrap(),
    );
    let witness = AuthorityJournal::create_encrypted(
        &f._dir.path().join("synthetic-independent-witness"),
        &DatabaseKey::from_bytes([43; 32]),
        policy,
    )
    .unwrap();
    // The synthetic helper records AcquireWriter at t and ActivateWriter at
    // t+1. Start just behind the wall clock so an immediately following control
    // cannot accidentally travel backward when both calls share a millisecond.
    synthetic::activate(
        &witness,
        &"b2".repeat(32),
        now_ms().unwrap().saturating_sub(2),
    )
    .unwrap();
    let snapshot = synthetic::snapshot(
        &witness,
        &"a1".repeat(32),
        "account-alice",
        AUTOMATION_PROFILE,
    )
    .unwrap();
    let witness_grant = WitnessAutomationGrant {
        account_policy_id: grant.policy.policy_id.clone(),
        binding: grant.binding.clone(),
        writer_epoch: 1,
        enrollment_ref: grant.enrollment_ref.clone(),
        agreement_ids: grant.terms.agreement_ids.clone(),
        recipient_scope_digests: vec![recipient_scope],
        maximum_payment_debit_zatoshis: grant.terms.maximum_payment_debit.as_zatoshis(),
        maximum_payment_fee_zatoshis: grant.terms.maximum_payment_fee.as_zatoshis(),
        maximum_outstanding_debit_zatoshis: grant.terms.maximum_outstanding_debit.as_zatoshis(),
        maximum_authorization_lifetime_ms: grant.terms.maximum_authorization_lifetime_ms,
        valid_from_ms: grant.terms.valid_from_ms,
        expires_at_ms: grant.terms.expires_at_ms,
        status: AutomationGrantStatus::Active,
    };
    let account_policy = WitnessAutomationAccountPolicy {
        policy_id: grant.policy.policy_id.clone(),
        writer_epoch: 1,
        maximum_outstanding_debit_zatoshis: grant.policy.maximum_outstanding_debit.as_zatoshis(),
        valid_from_ms: grant.policy.valid_from_ms,
        expires_at_ms: grant.policy.expires_at_ms,
    };
    let active = synthetic::control(
        &witness,
        &"a1".repeat(32),
        OwnerControlRequest {
            operation_id: "synthetic-native-grant-control".into(),
            account_id: "account-alice".into(),
            network_profile_id: AUTOMATION_PROFILE.into(),
            expected_head: snapshot.head,
            writer_epoch: 1,
            control: OwnerControl::SetAutomationGrant {
                grant: witness_grant,
                account_policy,
            },
        },
        now_ms().unwrap(),
    )
    .unwrap();
    let (evidence, continuation) = f
        .journal
        .record_automatic_consent_release(f.automatic(&grant))
        .unwrap();
    let request = RetainedAuthorizationRequest::from_original(
        &evidence,
        b"synthetic-automatic-storage-artifact",
        active.head,
        delivery,
    )
    .unwrap();
    let lease = f
        .journal
        .original_automatic_authorization_lease(
            "synthetic-auto-authorization",
            &f.session,
            &continuation,
        )
        .unwrap();
    f.journal.bridge_retain_request(&lease, &request).unwrap();
    let permit = synthetic::reserve(
        &witness,
        &"b2".repeat(32),
        request.reservation().clone(),
        now_ms().unwrap(),
    )
    .unwrap();
    f.journal.bridge_retain_permit(&lease, &permit).unwrap();
    assert!(f.journal.bridge_begin_key_use(&lease, &permit).is_err());
    assert!(
        f.journal
            .bridge_begin_authorized_key_use(&lease, &permit, None)
            .is_err()
    );
    let now = now_ms().unwrap();
    let admission = synthetic::authorize_automatic_key_use(
        &witness,
        &"b2".repeat(32),
        AuthorizeAutomaticKeyUse {
            operation_id: "synthetic-exact-auto-keyuse".into(),
            account_id: "account-alice".into(),
            network_profile_id: AUTOMATION_PROFILE.into(),
            writer_epoch: 1,
            expected_head: permit.descriptor().committed_head.clone(),
            reservation_operation_id: request.reservation().operation_id.clone(),
            reservation_request_digest: request.reservation().request_digest().unwrap(),
            automation: grant.binding.clone(),
            reviewed_at_ms: now,
            admission_expires_at_ms: request.reservation().permit_expires_at_ms,
        },
        now,
    )
    .unwrap();
    let historical = f
        .journal
        .acquire_original_authorization("synthetic-auto-authorization", &f.session)
        .unwrap();
    assert!(
        f.journal
            .bridge_begin_authorized_key_use(&historical, &permit, Some(&admission))
            .is_err()
    );
    drop(historical);
    f.journal
        .bridge_begin_authorized_key_use(&lease, &permit, Some(&admission))
        .unwrap();
    assert!(
        f.journal
            .bridge_begin_authorized_key_use(&lease, &permit, Some(&admission))
            .is_err()
    );
    assert_eq!(
        f.journal
            .connection
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM signer_automation_keyuse", [], |r| r
                .get::<_, u64>(
                0
            ))
            .unwrap(),
        1
    );
}

#[test]
fn automation_backup_preserves_grant_and_exact_consent_only_as_quarantined_history() {
    use std::collections::{BTreeMap, BTreeSet};
    use wholepact_storage_security::bundle::{recovery::VerifiedSignerRecoverySource, *};
    let f = Fixture::new();
    let grant = f.commit(f.prepared());
    let (original, _) = f
        .journal
        .record_automatic_consent_release(f.automatic(&grant))
        .unwrap();
    let adapter = f.journal.backup_adapter();
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
    let archive = f._dir.path().join("synthetic-automation-backup");
    let restored = f._dir.path().join("synthetic-quarantined-automation");
    let archive_key = DatabaseKey::from_bytes([44; 32]);
    let restored_key = DatabaseKey::from_bytes([45; 32]);
    let manifest = snapshot(SnapshotRequest {
        principal_id: "synthetic-owner",
        profile_id: "synthetic-signer-profile",
        coverage,
        sources: &sources,
        destination: &archive,
        key: &archive_key,
        authority: &crate::consent_journal::tests::BackupGate,
    })
    .unwrap();
    assert_eq!(manifest.components[0].schema_version, SCHEMA_VERSION);
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
        authority: &crate::consent_journal::tests::BackupGate,
    })
    .unwrap();
    assert!(!report.authorization_allowed);
    assert!(SignerConsentJournal::open_encrypted(
        &restored,
        &restored_key,
        "account-alice",
        &f.private_directory
            .signer_journal_source_owner_for_test(&restored)
            .unwrap()
    )
    .is_err());
    let source = VerifiedSignerRecoverySource::open(
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
    let grants = source
        .tables()
        .iter()
        .find(|t| t.name() == "signer_automation_grant_events")
        .unwrap();
    assert_eq!(grants.rows().len(), 1);
    let payload = grants
        .columns()
        .iter()
        .position(|s| s == "payload")
        .unwrap();
    let recovery::RecoveryCell::Text(raw) = &grants.rows()[0].cells()[payload] else {
        panic!("unexpected grant payload")
    };
    let retained: NativeAutomationGrantRecord = serde_json::from_str(raw).unwrap();
    assert_eq!(retained.reference().unwrap(), grant.reference().unwrap());
    let originals = source.original_consents().unwrap();
    assert_eq!(originals.rows().len(), 1);
    let payload = originals
        .columns()
        .iter()
        .position(|s| s == "payload")
        .unwrap();
    let recovery::RecoveryCell::Text(raw) = &originals.rows()[0].cells()[payload] else {
        panic!("unexpected consent payload")
    };
    let retained: OriginalSpendConsent = serde_json::from_str(raw).unwrap();
    assert_eq!(
        retained.reference(),
        original.original_consent().reference()
    );
    assert_eq!(
        retained.terms().automation.as_ref().unwrap().grant,
        grant.binding
    );
}

#[test]
fn restarted_native_owner_can_only_reduce_retained_same_epoch_grant() {
    let f = Fixture::new();
    let grant = f.commit(f.prepared());
    let (original, _) = f
        .journal
        .record_automatic_consent_release(f.automatic(&grant))
        .unwrap();
    let reopened = SignerConsentJournal::open_encrypted(
        &f.path,
        &f.key,
        "account-alice",
        &f.private_directory
            .signer_journal_source_owner_for_test(&f.path)
            .unwrap(),
    )
    .unwrap();
    let fresh = fixture::session(&reopened, "synthetic-owner");
    assert!(fresh
        .prepare_automation_grant(
            &reopened,
            &f.enrollment,
            grant.policy.clone(),
            grant.terms.clone(),
            grant.witness.clone(),
            AutomationGrantStatus::Active
        )
        .is_err());
    let prepare_pause = fresh
        .prepare_automation_grant(
            &reopened,
            &f.enrollment,
            grant.policy.clone(),
            grant.terms.clone(),
            grant.witness.clone(),
            AutomationGrantStatus::Paused,
        )
        .unwrap();
    let decision_pause = fixture::decision(&fresh, prepare_pause.review_digest());
    let paused = reopened
        .record_automation_grant(
            fresh
                .approve_automation_grant(prepare_pause, decision_pause)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(paused.binding.revision, 2);
    let mut changed = grant.terms.clone();
    changed.maximum_payment_fee = amount(30_001);
    assert!(
        fresh
            .prepare_automation_grant(
                &reopened,
                &f.enrollment,
                grant.policy.clone(),
                changed,
                grant.witness.clone(),
                AutomationGrantStatus::Revoked
            )
            .is_err()
    );
    let prepare = fresh
        .prepare_automation_grant(
            &reopened,
            &f.enrollment,
            grant.policy.clone(),
            grant.terms.clone(),
            grant.witness.clone(),
            AutomationGrantStatus::Revoked,
        )
        .unwrap();
    let decision = fixture::decision(&fresh, prepare.review_digest());
    let revoked = reopened
        .record_automation_grant(fresh.approve_automation_grant(prepare, decision).unwrap())
        .unwrap();
    assert_eq!(revoked.binding.revision, 3);
    assert_eq!(revoked.binding.terms_digest, grant.binding.terms_digest);
    assert_eq!(revoked.enrollment_ref, grant.enrollment_ref);
    assert!(revoked.status == AutomationGrantStatus::Revoked);
    assert_eq!(
        reopened
            .original_authorization("synthetic-auto-authorization", &fresh)
            .unwrap()
            .unwrap()
            .original_consent()
            .reference(),
        original.original_consent().reference()
    );
    let g = Fixture::new();
    let old = g.commit(g.prepared());
    g.journal
        .connection
        .lock()
        .unwrap()
        .execute("UPDATE signer_account SET writer_epoch=2", [])
        .unwrap();
    let successor = fixture::session(&g.journal, "synthetic-owner");
    assert!(
        successor
            .prepare_automation_grant(
                &g.journal,
                &g.enrollment,
                old.policy,
                old.terms,
                old.witness,
                AutomationGrantStatus::Revoked
            )
            .is_err()
    );
}
