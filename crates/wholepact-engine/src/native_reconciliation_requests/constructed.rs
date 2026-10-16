// Included inside the existing synthetic dispatch fixture module. Its predecessor
// uses the real constructor and modeled result metadata only, never proof/signing.
mod reconciliation_handoff {
    use super::*;
    use crate::native_reconciliation_requests::{
        self as reconciliation, NativeReconciliationRequest, NativeReconciliationRequestView,
    };
    fn queue_read(
        f: &Constructed,
        dispatch: &str,
        key: &str,
    ) -> crate::Result<NativeReconciliationRequestView> {
        f.engine.queue_native_reconciliation(
            &f.access,
            key,
            &f.agreement,
            f.revision(),
            NativeReconciliationRequest::ProviderObservation {
                dispatch_request_id: dispatch.into(),
            },
        )
    }
    fn started_dispatch(
        f: &Constructed,
        tx: &str,
        name: &str,
    ) -> (String, EncryptedSubmissionJournal) {
        let queued = request(f, tx, &format!("synthetic-reconciliation-dispatch-{name}")).unwrap();
        let actual = journal(f, &format!("reconciliation-{name}.sqlite"), 101);
        f.engine
            .mark_native_dispatch_attempt(
                &f.access,
                &f.agreement,
                &queued.request_id,
                actual.identity(),
            )
            .unwrap();
        (queued.request_id, actual)
    }
    #[test]
    fn exact_retry_private_unknown_fence_repeatable_reads_and_restart() {
        let (mut f, tx) = completed_metadata();
        let (dispatch, actual) = started_dispatch(&f, &tx, "repeatable");
        let original_revision = f.revision();
        let queued = queue_read(&f, &dispatch, "synthetic-observation-original").unwrap();
        assert_eq!(queued.dispatch_request_id, dispatch);
        assert_eq!(queued.submission_journal_identity, actual.identity());
        assert_eq!(queued.source.transaction_request_id, tx);
        assert!(!queued.authorization_allowed);
        assert!(queued.record_id.is_none());
        let replay = f
            .engine
            .queue_native_reconciliation(
                &f.access,
                "synthetic-observation-original",
                &f.agreement,
                original_revision,
                NativeReconciliationRequest::ProviderObservation {
                    dispatch_request_id: dispatch.clone(),
                },
            )
            .unwrap();
        assert_eq!(queued.request_id, replay.request_id);
        assert!(queue_read(&f, &dispatch, "synthetic-duplicate-queued").is_err());
        let attempt = f
            .engine
            .mark_native_reconciliation_attempt(&f.access, &f.agreement, &queued.request_id)
            .unwrap();
        // An actually empty journal permits historical inspection only, never the
        // provider-read or positive-resolution preflight, and cannot reset the fence.
        assert!(
            f.engine
                .validate_native_reconciliation_attempt(&f.access, &attempt, &actual)
                .is_err()
        );
        let observed = f
            .engine
            .inspect_native_reconciliation_status(&f.access, attempt.into_inspection(), &actual)
            .unwrap();
        assert_eq!(observed.outcome_status, "attempted_outcome_unknown");
        assert!(observed.resolution_commit.is_none());
        assert_eq!(observed.observations.len(), 1);
        assert!(observed.observations[0].report.is_none());
        assert!(observed.observations[0].submission.descriptor.is_none());
        let repeated = f
            .engine
            .inspect_native_reconciliation_status(
                &f.access,
                f.engine
                    .native_reconciliation_inspection(&f.access, &f.agreement, &queued.request_id)
                    .unwrap(),
                &actual,
            )
            .unwrap();
        assert_eq!(repeated.observations.len(), 1);
        let second = queue_read(&f, &dispatch, "synthetic-separate-observation").unwrap();
        assert_ne!(queued.request_id, second.request_id);
        assert_eq!(queued.operation_id, second.operation_id);
        assert_eq!(queued.source, second.source);
        f.restart();
        assert!(
            f.engine
                .mark_native_reconciliation_attempt(&f.access, &f.agreement, &queued.request_id)
                .is_err()
        );
        assert!(
            f.engine
                .withdraw_native_reconciliation_request(
                    &f.access,
                    "synthetic-cannot-withdraw-started",
                    &f.agreement,
                    f.revision(),
                    &queued.request_id
                )
                .is_err()
        );
        assert_eq!(
            f.engine
                .native_reconciliation_request(&f.access, &f.agreement, &queued.request_id)
                .unwrap()
                .observations
                .len(),
            1
        );
        let withdrawn = f
            .engine
            .withdraw_native_reconciliation_request(
                &f.access,
                "synthetic-withdraw-second",
                &f.agreement,
                f.revision(),
                &second.request_id,
            )
            .unwrap();
        assert_eq!(withdrawn.state, NativeRequestState::Withdrawn);
        let third = queue_read(&f, &dispatch, "synthetic-third-observation").unwrap();
        assert_ne!(third.request_id, second.request_id);
    }
    #[test]
    fn original_scope_foreign_principal_journal_and_missing_record_fail_closed() {
        let (f, tx) = completed_metadata();
        let unstarted = request(&f, &tx, "synthetic-unstarted-dispatch").unwrap();
        assert!(queue_read(&f, &unstarted.request_id, "synthetic-no-dispatch-attempt").is_err());
        let actual = journal(&f, "reconciliation-scope.sqlite", 102);
        f.engine
            .mark_native_dispatch_attempt(
                &f.access,
                &f.agreement,
                &unstarted.request_id,
                actual.identity(),
            )
            .unwrap();
        let foreign = Access {
            principal_id: "foreign-owner".into(),
            all_agreements: true,
            ..Access::default()
        };
        assert!(
            f.engine
                .queue_native_reconciliation(
                    &foreign,
                    "synthetic-foreign-original",
                    &f.agreement,
                    f.revision(),
                    NativeReconciliationRequest::ProviderObservation {
                        dispatch_request_id: unstarted.request_id.clone()
                    }
                )
                .is_err()
        );
        assert!(
            f.engine
                .queue_native_reconciliation(
                    &f.access,
                    "synthetic-missing-record",
                    &f.agreement,
                    f.revision(),
                    NativeReconciliationRequest::IndependentRecordResolution {
                        dispatch_request_id: unstarted.request_id.clone(),
                        participant_id: "participant-0".into(),
                        record_id: "unretained-record".into()
                    }
                )
                .is_err()
        );
        let queued = queue_read(&f, &unstarted.request_id, "synthetic-scope-read").unwrap();
        assert!(
            f.engine
                .native_reconciliation_request(&foreign, &f.agreement, &queued.request_id)
                .is_err()
        );
        assert!(
            f.engine
                .native_reconciliation_requests(&foreign, &f.agreement)
                .unwrap()
                .is_empty()
        );
        let attempt = f
            .engine
            .mark_native_reconciliation_attempt(&f.access, &f.agreement, &queued.request_id)
            .unwrap();
        let wrong = journal(&f, "reconciliation-wrong.sqlite", 103);
        assert!(
            f.engine
                .inspect_native_reconciliation_status(&f.access, attempt.into_inspection(), &wrong)
                .is_err()
        );
        assert!(
            f.engine
                .native_reconciliation_request(&f.access, &f.agreement, &queued.request_id)
                .unwrap()
                .observations
                .is_empty()
        );
    }
    #[test]
    fn shared_quota_includes_all_preserved_reconciliation_attempts() {
        let (f, tx) = completed_metadata();
        let (dispatch, _actual) = started_dispatch(&f, &tx, "quota");
        loop {
            let e = f.engine.load(&f.access, &f.agreement).unwrap();
            let count = crate::native_requests::total_requests(&e);
            if count == crate::native_requests::MAX_NATIVE_REQUESTS {
                break;
            }
            let queued = queue_read(
                &f,
                &dispatch,
                &format!("synthetic-reconciliation-quota-{count}"),
            )
            .unwrap();
            f.engine
                .mark_native_reconciliation_attempt(&f.access, &f.agreement, &queued.request_id)
                .unwrap();
        }
        assert_eq!(
            queue_read(&f, &dispatch, "synthetic-reconciliation-overflow")
                .unwrap_err()
                .code,
            "RESOURCE_EXHAUSTED"
        );
        assert!(
            f.engine
                .native_reconciliation_requests(&f.access, &f.agreement)
                .unwrap()
                .iter()
                .all(|r| r.state == NativeRequestState::AttemptStarted)
        );
    }
    #[test]
    fn immutable_source_and_no_claimed_positive_completion_are_revalidated() {
        let (f, tx) = completed_metadata();
        let (dispatch, _actual) = started_dispatch(&f, &tx, "tamper");
        let queued = queue_read(&f, &dispatch, "synthetic-reconciliation-tamper").unwrap();
        f.engine
            .mark_native_reconciliation_attempt(&f.access, &f.agreement, &queued.request_id)
            .unwrap();
        let original = f
            .engine
            .store
            .get_agreement(&f.agreement)
            .unwrap()
            .unwrap()
            .payload;
        for field in ["operation_id", "submission_journal_identity", "source"] {
            let mut bad = original.clone();
            bad["native_reconciliation_requests"][&queued.request_id][field] = if field == "source"
            {
                json!({})
            } else {
                json!("ff".repeat(32))
            };
            let valid = serde_json::from_value::<Envelope>(bad)
                .is_ok_and(|e| reconciliation::validate_stored(&e).is_ok());
            assert!(!valid, "{field}");
        }
        let mut bad = original;
        bad["native_reconciliation_requests"][&queued.request_id]["resolution_commit"] = json!({"evidence_id":"11".repeat(32),"signer_settlement_request_digest":"22".repeat(32),"participant_id":"participant-0","record_id":"fake"});
        assert!(
            reconciliation::validate_stored(&serde_json::from_value::<Envelope>(bad).unwrap())
                .is_err()
        );
    }
    use crate::participant_records::{
        ParticipantRecordAction, ParticipantRecordAuthority, ParticipantRecordLease,
        ParticipantRecordRuntime, ParticipantRecordScope, RecordStoreBinding,
        RetainParticipantRecordRequest, RetainedParticipantRecordSource,
    };
    use wholepact_core::records::{
        ExactTransactionReference, ObservationWindow, OwnAuthorizationRecord, SettlementRecord,
    };
    struct SyntheticRecordGate {
        binding: RecordStoreBinding,
        principal: String,
        account: String,
        revoked: AtomicBool,
        expired: AtomicBool,
    }
    struct SyntheticRecordLease<'a> {
        gate: &'a SyntheticRecordGate,
        scope: ParticipantRecordScope,
    }
    impl ParticipantRecordLease for SyntheticRecordLease<'_> {
        fn scope(&self) -> &ParticipantRecordScope {
            &self.scope
        }
        fn expires_at(&self) -> &str {
            if self.gate.expired.load(Ordering::SeqCst) {
                "2026-10-15T00:00:00Z"
            } else {
                "2026-10-16T00:00:00Z"
            }
        }
        fn check_current(&self) -> crate::Result<()> {
            if self.gate.revoked.load(Ordering::SeqCst) {
                Err(ApiError::new(
                    "PERMISSION_DENIED",
                    "Synthetic record lease revoked",
                ))
            } else {
                Ok(())
            }
        }
    }
    impl ParticipantRecordAuthority for SyntheticRecordGate {
        fn acquire<'a>(
            &'a self,
            s: &ParticipantRecordScope,
            _: &ObservationWindow,
        ) -> crate::Result<Box<dyn ParticipantRecordLease + 'a>> {
            if s.store != self.binding
                || s.principal_id != self.principal
                || s.account_id != self.account
                || s.participant_id != "participant-0"
                || s.profile_id != "synthetic-record-profile"
                || !matches!(
                    s.action,
                    ParticipantRecordAction::Retain | ParticipantRecordAction::ReadPrivate
                )
            {
                return Err(ApiError::new(
                    "PERMISSION_DENIED",
                    "Synthetic record scope mismatch",
                ));
            }
            Ok(Box::new(SyntheticRecordLease {
                gate: self,
                scope: s.clone(),
            }))
        }
    }
    struct ModeledRecordSource {
        txid: String,
        bytes: String,
        signed_artifact: String,
    }
    impl RetainedParticipantRecordSource for ModeledRecordSource {
        fn source_id(&self) -> &str {
            "synthetic-modeled-record-source"
        }
        fn load_retained_record(
            &mut self,
            r: &RetainParticipantRecordRequest,
            c: &Proposal,
        ) -> crate::Result<SettlementRecord> {
            let mut input = c.input().clone();
            input.artifact_digest = Some(self.signed_artifact.clone());
            input.effects_commitment = Some("72".repeat(32));
            let approved = Proposal::validate(input)?;
            let own = OwnAuthorizationRecord {
                participant_id: r.participant_id.clone(),
                account_id: r.account_id.clone(),
                proposal_digest: approved.proposal_digest().into(),
                manifest_digest: approved.manifest_digest().into(),
                effects_commitment: "72".repeat(32),
                consent_record_ref: "PRIVATE-SYNTHETIC-CONSENT-SENTINEL".into(),
                authorization_record_ref: "PRIVATE-SYNTHETIC-AUTH-SENTINEL".into(),
                release_operation_id: Some("PRIVATE-SYNTHETIC-AUTH-SENTINEL".into()),
                exposure: AuthorizationExposure::Released,
            };
            Ok(SettlementRecord::new(
                r.record_id.clone(),
                approved,
                own,
                ExactTransactionReference {
                    network_profile_id: PROFILE_ID.into(),
                    transaction_id: self.txid.clone(),
                    transaction_bytes_digest: self.bytes.clone(),
                    effects_commitment: "72".repeat(32),
                },
            )?)
        }
    }
    fn record_window() -> ObservationWindow {
        ObservationWindow {
            now: "2026-10-15T21:00:00Z".into(),
            oldest_acceptable: "2026-10-15T20:55:00Z".into(),
        }
    }
    fn retain_modeled_record(f: &Constructed, dispatch: &str) -> SyntheticRecordGate {
        let original = f
            .engine
            .native_dispatch_request(&f.access, &f.agreement, dispatch)
            .unwrap();
        let (_, candidate) = f.engine.candidate(&f.access, &f.candidate).unwrap();
        let account = candidate.proposal.manifest.participants[0]
            .account_id
            .clone();
        let gate = SyntheticRecordGate {
            binding: f.engine.protected_record_store_binding().unwrap(),
            principal: f.access.principal_id.clone(),
            account: account.clone(),
            revoked: AtomicBool::new(false),
            expired: AtomicBool::new(false),
        };
        f.engine
            .retain_participant_record(
                &f.access,
                "synthetic-retain-reconciliation-record",
                &f.agreement,
                f.revision(),
                RetainParticipantRecordRequest {
                    record_id: "synthetic-existing-record".into(),
                    candidate_id: f.candidate.clone(),
                    participant_id: "participant-0".into(),
                    account_id: account,
                },
                ParticipantRecordRuntime {
                    profile_id: "synthetic-record-profile",
                    authority: &gate,
                    window: &record_window(),
                },
                &mut ModeledRecordSource {
                    txid: original.source.txid,
                    bytes: original.source.transaction_digest,
                    signed_artifact: original.source.signed.signed_candidate_digest,
                },
            )
            .unwrap();
        gate
    }
    #[test]
    fn selected_record_is_exact_principal_owned_and_does_not_disclose_archive() {
        let (f, tx) = completed_metadata();
        let (dispatch, _actual) = started_dispatch(&f, &tx, "record-selection");
        let _gate = retain_modeled_record(&f, &dispatch);
        for (participant, record) in [
            ("participant-1", "synthetic-existing-record"),
            ("participant-0", "missing-record"),
            (".", "synthetic-existing-record"),
        ] {
            assert!(
                f.engine
                    .queue_native_reconciliation(
                        &f.access,
                        &format!("synthetic-bad-record-{participant}-{record}"),
                        &f.agreement,
                        f.revision(),
                        NativeReconciliationRequest::IndependentRecordResolution {
                            dispatch_request_id: dispatch.clone(),
                            participant_id: participant.into(),
                            record_id: record.into()
                        }
                    )
                    .is_err()
            );
        }
        let queued = f
            .engine
            .queue_native_reconciliation(
                &f.access,
                "synthetic-selected-record-request",
                &f.agreement,
                f.revision(),
                NativeReconciliationRequest::IndependentRecordResolution {
                    dispatch_request_id: dispatch,
                    participant_id: "participant-0".into(),
                    record_id: "synthetic-existing-record".into(),
                },
            )
            .unwrap();
        let text = serde_json::to_string(&queued).unwrap();
        for private in [
            "PRIVATE-SYNTHETIC-CONSENT-SENTINEL",
            "PRIVATE-SYNTHETIC-AUTH-SENTINEL",
            "own_authorization",
            "exposure",
            "profile_id",
            "account_id",
        ] {
            assert!(!text.contains(private), "{private}");
        }
        assert_eq!(
            queued.record_id.as_deref(),
            Some("synthetic-existing-record")
        );
        assert!(queued.resolution_commit.is_none());
    }
    #[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
    #[test]
    fn held_record_guard_rechecks_revocation_but_preserves_mutable_confidence_updates() {
        let (f, tx) = completed_metadata();
        let (dispatch, _actual) = started_dispatch(&f, &tx, "record-guard");
        let gate = retain_modeled_record(&f, &dispatch);
        let queued = f
            .engine
            .queue_native_reconciliation(
                &f.access,
                "synthetic-guard-request",
                &f.agreement,
                f.revision(),
                NativeReconciliationRequest::IndependentRecordResolution {
                    dispatch_request_id: dispatch,
                    participant_id: "participant-0".into(),
                    record_id: "synthetic-existing-record".into(),
                },
            )
            .unwrap();
        let attempt = f
            .engine
            .mark_native_reconciliation_attempt(&f.access, &f.agreement, &queued.request_id)
            .unwrap();
        let window = record_window();
        let runtime = ParticipantRecordRuntime {
            profile_id: "synthetic-record-profile",
            authority: &gate,
            window: &window,
        };
        let guard = f
            .engine
            .prepare_native_record_resolution(&f.access, &attempt, &runtime)
            .unwrap();
        assert!(guard.check_current().is_ok());
        // Model only mutable archival confidence/exposure fields; no positive
        // permit or signer receipt is fabricated and no resolution is invoked.
        let mut payload = f
            .engine
            .store
            .get_agreement(&f.agreement)
            .unwrap()
            .unwrap()
            .payload;
        payload["participant_records"]["synthetic-existing-record"]["record_revision"] = json!(2);
        payload["participant_records"]["synthetic-existing-record"]["record"]["own_authorization"]
            ["exposure"] = json!("consumed");
        let e: Envelope = serde_json::from_value(payload).unwrap();
        let revision = f.revision();
        let command = context(
            &f.access,
            "synthetic-modeled-confidence-update",
            "synthetic_modeled_confidence_update",
            &f.agreement,
            Some(revision),
            &json!({"modeled":true}),
        )
        .unwrap();
        // Keep the genuine synthetic record lease alive and check immediately
        // before and after this modeled metadata commit, as the production wrapper
        // does around its separately genuine independent-resolution operation.
        guard.check_current().unwrap();
        f.engine
            .commit(
                &command,
                &f.agreement,
                revision,
                e,
                "synthetic_modeled_confidence_update",
            )
            .unwrap();
        assert!(guard.check_current().is_ok());
        assert!(
            f.engine
                .native_reconciliation_request(&f.access, &f.agreement, &queued.request_id)
                .unwrap()
                .resolution_commit
                .is_none()
        );
        gate.revoked.store(true, Ordering::SeqCst);
        let effects = AtomicUsize::new(0);
        let blocked = (|| -> crate::Result<()> {
            guard.check_current()?;
            effects.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })();
        assert!(blocked.is_err());
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        gate.revoked.store(false, Ordering::SeqCst);
        assert!(guard.check_current().is_ok());

        // An archive with a substituted original consent reference still has a
        // syntactically valid record but must fail this already-held exact guard.
        let mut payload = f
            .engine
            .store
            .get_agreement(&f.agreement)
            .unwrap()
            .unwrap()
            .payload;
        payload["participant_records"]["synthetic-existing-record"]["record"]["own_authorization"]
            ["consent_record_ref"] = json!("PRIVATE-SUBSTITUTED-CONSENT-SENTINEL");
        let e: Envelope = serde_json::from_value(payload).unwrap();
        let revision = f.revision();
        let command = context(
            &f.access,
            "synthetic-modeled-consent-substitution",
            "synthetic_modeled_consent_substitution",
            &f.agreement,
            Some(revision),
            &json!({"modeled_negative":true}),
        )
        .unwrap();
        f.engine
            .commit(
                &command,
                &f.agreement,
                revision,
                e,
                "synthetic_modeled_consent_substitution",
            )
            .unwrap();
        let blocked = (|| -> crate::Result<()> {
            guard.check_current()?;
            effects.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })();
        assert!(blocked.is_err());
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        assert!(
            f.engine
                .native_reconciliation_request(&f.access, &f.agreement, &queued.request_id)
                .unwrap()
                .resolution_commit
                .is_none()
        );
    }
    #[cfg(all(feature = "signer-authority-bridge", target_os = "linux"))]
    #[test]
    fn selected_permission_expiry_or_revocation_at_store_precommit_rolls_back() {
        for expire in [false, true] {
            let (f, tx) = completed_metadata();
            let (dispatch, _actual) = started_dispatch(&f, &tx, "precommit");
            let gate = retain_modeled_record(&f, &dispatch);
            let queued = f
                .engine
                .queue_native_reconciliation(
                    &f.access,
                    "synthetic-precommit-request",
                    &f.agreement,
                    f.revision(),
                    NativeReconciliationRequest::IndependentRecordResolution {
                        dispatch_request_id: dispatch,
                        participant_id: "participant-0".into(),
                        record_id: "synthetic-existing-record".into(),
                    },
                )
                .unwrap();
            let attempt = f
                .engine
                .mark_native_reconciliation_attempt(&f.access, &f.agreement, &queued.request_id)
                .unwrap();
            let window = record_window();
            let runtime = ParticipantRecordRuntime {
                profile_id: "synthetic-record-profile",
                authority: &gate,
                window: &window,
            };
            let guard = f
                .engine
                .prepare_native_record_resolution(&f.access, &attempt, &runtime)
                .unwrap();
            guard.check_current().unwrap();
            let snapshot = f.engine.store.list_agreements().unwrap();
            let release = wholepact_store::authority::ReleaseIntent {
                authorization_id: "synthetic-precommit-original".into(),
                account_id: gate.account.clone(),
                writer_epoch: 1,
                obligation_id: "synthetic-precommit-obligation".into(),
                proposal_id: "synthetic-precommit-proposal".into(),
                manifest_digest: "91".repeat(32),
                effects_digest: "92".repeat(32),
                artifact_digest: "93".repeat(32),
                maximum_debit: "7".into(),
                input_ids: vec!["synthetic-precommit-nullifier".into()],
                aggregate_budget_limit: "20".into(),
            };
            let reached = AtomicBool::new(false);
            // Exercise the actual Store rollback boundary with the same private
            // permission predicate used by checked apply; no signer/node permit.
            let result = f.engine.store.consume_exact_settlement_release(
                &release,
                "synthetic-precommit-evidence",
                &json!({"storage_test_only":true}),
                &snapshot,
                &[],
                &|| {
                    reached.store(true, Ordering::SeqCst);
                    if expire {
                        gate.expired.store(true, Ordering::SeqCst);
                    } else {
                        gate.revoked.store(true, Ordering::SeqCst);
                    }
                    guard
                        .check_commit_permission()
                        .map_err(|_| wholepact_store::StoreError::RecoveryRequired)
                },
            );
            assert!(reached.load(Ordering::SeqCst));
            assert!(result.is_err());
            assert!(
                f.engine
                    .store
                    .exposure(&release.authorization_id)
                    .unwrap()
                    .is_none()
            );
            assert!(
                f.engine
                    .store
                    .authority_account(&release.account_id)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(f.engine.store.list_agreements().unwrap(), snapshot);
            assert!(
                f.engine
                    .native_reconciliation_request(&f.access, &f.agreement, &queued.request_id)
                    .unwrap()
                    .resolution_commit
                    .is_none()
            );
        }
    }
}
