CREATE TABLE signer_account (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), account_id TEXT NOT NULL,
 writer_epoch INTEGER NOT NULL CHECK(writer_epoch>0), recovery_required INTEGER NOT NULL CHECK(recovery_required IN(0,1))
);
CREATE TABLE signer_enrollments (
 reference TEXT PRIMARY KEY, account_id TEXT NOT NULL, agreement_id TEXT NOT NULL,
 participant_id TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE TABLE signer_accepted_manifests (
 reference TEXT PRIMARY KEY, enrollment_ref TEXT NOT NULL REFERENCES signer_enrollments(reference),
 proposal_id TEXT NOT NULL, proposal_digest TEXT NOT NULL, payload TEXT NOT NULL,
 UNIQUE(enrollment_ref,proposal_id)
);
CREATE TABLE signer_original_consents (
 reference TEXT PRIMARY KEY, enrollment_ref TEXT NOT NULL REFERENCES signer_enrollments(reference),
 manifest_ref TEXT NOT NULL REFERENCES signer_accepted_manifests(reference),
 authorization_id TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE, payload TEXT NOT NULL
);
CREATE TABLE signer_release_intents (
 authorization_id TEXT PRIMARY KEY, original_consent_ref TEXT NOT NULL UNIQUE REFERENCES signer_original_consents(reference),
 account_id TEXT NOT NULL, obligation_id TEXT NOT NULL, maximum_debit TEXT NOT NULL,
 payload TEXT NOT NULL, exposure_state TEXT NOT NULL CHECK(exposure_state='outstanding_uncertain'),
 UNIQUE(account_id,obligation_id)
);
CREATE TABLE signer_input_reservations (
 account_id TEXT NOT NULL, input_id TEXT NOT NULL,
 authorization_id TEXT NOT NULL REFERENCES signer_release_intents(authorization_id),
 PRIMARY KEY(account_id,input_id)
);
CREATE TRIGGER signer_enrollments_no_update BEFORE UPDATE ON signer_enrollments BEGIN SELECT RAISE(ABORT,'immutable signer enrollment'); END;
CREATE TRIGGER signer_enrollments_no_delete BEFORE DELETE ON signer_enrollments BEGIN SELECT RAISE(ABORT,'immutable signer enrollment'); END;
CREATE TRIGGER signer_manifests_no_update BEFORE UPDATE ON signer_accepted_manifests BEGIN SELECT RAISE(ABORT,'immutable accepted manifest'); END;
CREATE TRIGGER signer_manifests_no_delete BEFORE DELETE ON signer_accepted_manifests BEGIN SELECT RAISE(ABORT,'immutable accepted manifest'); END;
CREATE TRIGGER signer_consents_no_update BEFORE UPDATE ON signer_original_consents BEGIN SELECT RAISE(ABORT,'immutable original consent'); END;
CREATE TRIGGER signer_consents_no_delete BEFORE DELETE ON signer_original_consents BEGIN SELECT RAISE(ABORT,'immutable original consent'); END;
CREATE TRIGGER signer_releases_no_update BEFORE UPDATE ON signer_release_intents BEGIN SELECT RAISE(ABORT,'immutable release intent'); END;
CREATE TRIGGER signer_releases_no_delete BEFORE DELETE ON signer_release_intents BEGIN SELECT RAISE(ABORT,'immutable release intent'); END;

CREATE TABLE signer_bridge_requests (
 authorization_id TEXT PRIMARY KEY REFERENCES signer_release_intents(authorization_id),
 original_consent_ref TEXT NOT NULL UNIQUE REFERENCES signer_original_consents(reference),
 request_payload TEXT NOT NULL, artifact_hex TEXT NOT NULL
);
CREATE TABLE signer_bridge_permits (
 authorization_id TEXT PRIMARY KEY REFERENCES signer_bridge_requests(authorization_id), payload TEXT NOT NULL
);
CREATE TABLE signer_bridge_keyuse (
 authorization_id TEXT PRIMARY KEY REFERENCES signer_bridge_permits(authorization_id)
);
CREATE TABLE signer_bridge_results (
 authorization_id TEXT PRIMARY KEY REFERENCES signer_bridge_keyuse(authorization_id),
 result_digest TEXT NOT NULL, result_hex TEXT NOT NULL, outbox_payload TEXT NOT NULL
);
CREATE TRIGGER signer_bridge_requests_no_update BEFORE UPDATE ON signer_bridge_requests BEGIN SELECT RAISE(ABORT,'immutable signer bridge requests'); END;
CREATE TRIGGER signer_bridge_requests_no_delete BEFORE DELETE ON signer_bridge_requests BEGIN SELECT RAISE(ABORT,'immutable signer bridge requests'); END;
CREATE TRIGGER signer_bridge_permits_no_update BEFORE UPDATE ON signer_bridge_permits BEGIN SELECT RAISE(ABORT,'immutable signer bridge permits'); END;
CREATE TRIGGER signer_bridge_permits_no_delete BEFORE DELETE ON signer_bridge_permits BEGIN SELECT RAISE(ABORT,'immutable signer bridge permits'); END;
CREATE TRIGGER signer_bridge_keyuse_no_update BEFORE UPDATE ON signer_bridge_keyuse BEGIN SELECT RAISE(ABORT,'immutable signer bridge keyuse'); END;
CREATE TRIGGER signer_bridge_keyuse_no_delete BEFORE DELETE ON signer_bridge_keyuse BEGIN SELECT RAISE(ABORT,'immutable signer bridge keyuse'); END;
CREATE TRIGGER signer_bridge_results_no_update BEFORE UPDATE ON signer_bridge_results BEGIN SELECT RAISE(ABORT,'immutable signer bridge results'); END;
CREATE TRIGGER signer_bridge_results_no_delete BEFORE DELETE ON signer_bridge_results BEGIN SELECT RAISE(ABORT,'immutable signer bridge results'); END;

-- Authenticated remote copies remain evidence of conservative exposure only.
-- They never populate original-consent, release-intent or signing-token tables.
CREATE TABLE signer_remote_exposures (
 authorization_id TEXT PRIMARY KEY, original_consent_ref TEXT NOT NULL,
 account_id TEXT NOT NULL, obligation_id TEXT NOT NULL, maximum_debit TEXT NOT NULL,
 payload TEXT NOT NULL
);
CREATE TABLE signer_remote_inputs (
 authorization_id TEXT NOT NULL REFERENCES signer_remote_exposures(authorization_id),
 account_id TEXT NOT NULL, nullifier TEXT NOT NULL,
 PRIMARY KEY(authorization_id,nullifier)
);
CREATE TABLE signer_writer_reconciliations (
 review_digest TEXT PRIMARY KEY, disclosure TEXT NOT NULL,
 head_sequence INTEGER NOT NULL, head_digest TEXT NOT NULL,
 writer_epoch INTEGER NOT NULL, payload TEXT NOT NULL
);
CREATE TRIGGER signer_remote_exposures_no_update BEFORE UPDATE ON signer_remote_exposures BEGIN SELECT RAISE(ABORT,'immutable remote exposure'); END;
CREATE TRIGGER signer_remote_exposures_no_delete BEFORE DELETE ON signer_remote_exposures BEGIN SELECT RAISE(ABORT,'immutable remote exposure'); END;
CREATE TRIGGER signer_remote_inputs_no_update BEFORE UPDATE ON signer_remote_inputs BEGIN SELECT RAISE(ABORT,'immutable remote input'); END;
CREATE TRIGGER signer_remote_inputs_no_delete BEFORE DELETE ON signer_remote_inputs BEGIN SELECT RAISE(ABORT,'immutable remote input'); END;
CREATE TRIGGER signer_writer_reconciliations_no_update BEFORE UPDATE ON signer_writer_reconciliations BEGIN SELECT RAISE(ABORT,'immutable reconciliation'); END;
CREATE TRIGGER signer_writer_reconciliations_no_delete BEFORE DELETE ON signer_writer_reconciliations BEGIN SELECT RAISE(ABORT,'immutable reconciliation'); END;

CREATE TABLE signer_result_redeliveries (
 operation_id TEXT PRIMARY KEY, reference TEXT NOT NULL UNIQUE,
 authorization_id TEXT NOT NULL REFERENCES signer_bridge_results(authorization_id), payload TEXT NOT NULL
);
CREATE TRIGGER signer_redeliveries_no_update BEFORE UPDATE ON signer_result_redeliveries BEGIN SELECT RAISE(ABORT,'immutable exact result redelivery'); END;
CREATE TRIGGER signer_redeliveries_no_delete BEFORE DELETE ON signer_result_redeliveries BEGIN SELECT RAISE(ABORT,'immutable exact result redelivery'); END;

-- Exact durable witness retry payload, never a native approval.
CREATE TABLE signer_dispatch_requests (
 operation_id TEXT PRIMARY KEY,
 authorization_id TEXT NOT NULL REFERENCES signer_bridge_results(authorization_id), payload TEXT NOT NULL
);
CREATE TRIGGER signer_dispatch_no_update BEFORE UPDATE ON signer_dispatch_requests BEGIN SELECT RAISE(ABORT,'immutable exact dispatch request'); END;
CREATE TRIGGER signer_dispatch_no_delete BEFORE DELETE ON signer_dispatch_requests BEGIN SELECT RAISE(ABORT,'immutable exact dispatch request'); END;

-- Native-approved canonical source identity; imported JSON is never enrollment.
CREATE TABLE signer_settlement_sources (
 reference TEXT PRIMARY KEY, account_id TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE TABLE signer_settlement_events (
 sequence INTEGER PRIMARY KEY,
 evidence_id TEXT NOT NULL, authorization_id TEXT NOT NULL REFERENCES signer_release_intents(authorization_id),
 source_ref TEXT NOT NULL REFERENCES signer_settlement_sources(reference),
 kind TEXT NOT NULL CHECK(kind IN ('canonical_consumed','canonical_conflict','reopened')),
 payload TEXT NOT NULL, UNIQUE(evidence_id,authorization_id,kind)
);
CREATE TRIGGER signer_settlement_sources_no_update BEFORE UPDATE ON signer_settlement_sources BEGIN SELECT RAISE(ABORT,'immutable settlement source'); END;
CREATE TRIGGER signer_settlement_sources_no_delete BEFORE DELETE ON signer_settlement_sources BEGIN SELECT RAISE(ABORT,'immutable settlement source'); END;
CREATE TRIGGER signer_settlement_events_no_update BEFORE UPDATE ON signer_settlement_events BEGIN SELECT RAISE(ABORT,'immutable settlement history'); END;
CREATE TRIGGER signer_settlement_events_no_delete BEFORE DELETE ON signer_settlement_events BEGIN SELECT RAISE(ABORT,'immutable settlement history'); END;

-- Native sponsor controls and owner attributions are durable original evidence.
CREATE TABLE signer_sponsor_policy_events (
 policy_key TEXT NOT NULL, version INTEGER NOT NULL CHECK(version>0), payload TEXT NOT NULL,
 PRIMARY KEY(policy_key,version)
);
CREATE TABLE signer_sponsor_manifest_bindings (
 manifest_ref TEXT PRIMARY KEY REFERENCES signer_accepted_manifests(reference),
 policy_key TEXT NOT NULL, version INTEGER NOT NULL, payload TEXT NOT NULL,
 FOREIGN KEY(policy_key,version) REFERENCES signer_sponsor_policy_events(policy_key,version)
);
CREATE TABLE signer_sponsor_owner_attestations (
 manifest_ref TEXT PRIMARY KEY REFERENCES signer_sponsor_manifest_bindings(manifest_ref), payload TEXT NOT NULL
);
CREATE TRIGGER signer_sponsor_events_no_update BEFORE UPDATE ON signer_sponsor_policy_events BEGIN SELECT RAISE(ABORT,'immutable native sponsor event'); END;
CREATE TRIGGER signer_sponsor_events_no_delete BEFORE DELETE ON signer_sponsor_policy_events BEGIN SELECT RAISE(ABORT,'immutable native sponsor event'); END;
CREATE TRIGGER signer_sponsor_bindings_no_update BEFORE UPDATE ON signer_sponsor_manifest_bindings BEGIN SELECT RAISE(ABORT,'immutable native sponsor binding'); END;
CREATE TRIGGER signer_sponsor_bindings_no_delete BEFORE DELETE ON signer_sponsor_manifest_bindings BEGIN SELECT RAISE(ABORT,'immutable native sponsor binding'); END;
CREATE TRIGGER signer_sponsor_attestations_no_update BEFORE UPDATE ON signer_sponsor_owner_attestations BEGIN SELECT RAISE(ABORT,'immutable native sponsor attribution'); END;
CREATE TRIGGER signer_sponsor_attestations_no_delete BEFORE DELETE ON signer_sponsor_owner_attestations BEGIN SELECT RAISE(ABORT,'immutable native sponsor attribution'); END;

-- Append-only generation commit evidence. An ordinary journal opener must refuse
-- any recovered generation; AccountVault verifies its final profile manifest.
CREATE TABLE signer_recovery_generations (
 generation_id TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN ('prepared','committed')),
 operation_id TEXT NOT NULL, inventory_digest TEXT NOT NULL, fence_digest TEXT NOT NULL,
 writer_epoch INTEGER NOT NULL CHECK(writer_epoch>0), payload TEXT NOT NULL,
 PRIMARY KEY(generation_id,phase)
);
CREATE TRIGGER signer_recovery_generations_no_update BEFORE UPDATE ON signer_recovery_generations BEGIN SELECT RAISE(ABORT,'immutable recovery generation'); END;
CREATE TRIGGER signer_recovery_generations_no_delete BEFORE DELETE ON signer_recovery_generations BEGIN SELECT RAISE(ABORT,'immutable recovery generation'); END;

-- Native-approved automation history is audit evidence, never an imported capability.
CREATE TABLE signer_automation_grant_events (
 grant_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0),
 enrollment_ref TEXT NOT NULL REFERENCES signer_enrollments(reference), payload TEXT NOT NULL,
 PRIMARY KEY(grant_id,revision)
);
CREATE TRIGGER signer_automation_grants_no_update BEFORE UPDATE ON signer_automation_grant_events BEGIN SELECT RAISE(ABORT,'immutable native automation grant'); END;
CREATE TRIGGER signer_automation_grants_no_delete BEFORE DELETE ON signer_automation_grant_events BEGIN SELECT RAISE(ABORT,'immutable native automation grant'); END;

CREATE TABLE signer_automation_keyuse (
 authorization_id TEXT PRIMARY KEY REFERENCES signer_bridge_keyuse(authorization_id), payload TEXT NOT NULL
);
CREATE TRIGGER signer_automation_keyuse_no_update BEFORE UPDATE ON signer_automation_keyuse BEGIN SELECT RAISE(ABORT,'immutable automatic key-use admission'); END;
CREATE TRIGGER signer_automation_keyuse_no_delete BEFORE DELETE ON signer_automation_keyuse BEGIN SELECT RAISE(ABORT,'immutable automatic key-use admission'); END;

-- Offline reservation intent is not original spending consent. Keep its origin
-- separate from the legacy online-only original_consent_ref schema.
CREATE TABLE signer_offline_enrollments (
 policy_digest TEXT PRIMARY KEY, enrollment_ref TEXT NOT NULL,
 account_id TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE TABLE signer_offline_intents (
 intent_digest TEXT PRIMARY KEY, authorization_id TEXT NOT NULL UNIQUE,
 policy_digest TEXT NOT NULL REFERENCES signer_offline_enrollments(policy_digest), payload TEXT NOT NULL
);
CREATE TABLE signer_offline_admissions (
 authorization_id TEXT PRIMARY KEY REFERENCES signer_offline_intents(authorization_id),
 request_digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL
);
-- Every imported admission remains potential exposure, regardless of expiry,
-- revocation, missing result or positive observations in an old restored copy.
CREATE TABLE signer_offline_remote_exposures (
 authorization_id TEXT PRIMARY KEY REFERENCES signer_offline_admissions(authorization_id),
 account_id TEXT NOT NULL, obligation_id TEXT NOT NULL, maximum_debit TEXT NOT NULL,
 payload TEXT NOT NULL
);
CREATE TABLE signer_offline_remote_inputs (
 authorization_id TEXT NOT NULL REFERENCES signer_offline_remote_exposures(authorization_id),
 account_id TEXT NOT NULL, nullifier TEXT NOT NULL,
 PRIMARY KEY(authorization_id,nullifier)
);
-- Minimal offline-device origin. No witness account totals, controller session
-- or owner policy are required. Every admitted effect counts before consent.
CREATE TABLE signer_offline_local_admissions (
 authorization_id TEXT PRIMARY KEY, account_id TEXT NOT NULL,
 obligation_id TEXT NOT NULL, maximum_debit TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE TABLE signer_offline_local_inputs (
 authorization_id TEXT NOT NULL REFERENCES signer_offline_local_admissions(authorization_id),
 account_id TEXT NOT NULL, nullifier TEXT NOT NULL,
 PRIMARY KEY(authorization_id,nullifier)
);
-- Native final decision is independently retained, never populated by witness
-- history import or reservation-intent review. No spending issuer is enabled.
CREATE TABLE signer_offline_original_consents (
 reference TEXT PRIMARY KEY, authorization_id TEXT NOT NULL UNIQUE REFERENCES signer_offline_local_admissions(authorization_id),
 account_id TEXT NOT NULL, nonce TEXT NOT NULL UNIQUE, payload TEXT NOT NULL
);
CREATE TABLE signer_offline_keyuse (
 authorization_id TEXT PRIMARY KEY REFERENCES signer_offline_original_consents(authorization_id),
 original_consent_ref TEXT NOT NULL UNIQUE REFERENCES signer_offline_original_consents(reference), payload TEXT NOT NULL
);
CREATE TABLE signer_offline_results (
 authorization_id TEXT PRIMARY KEY REFERENCES signer_offline_keyuse(authorization_id),
 result_digest TEXT NOT NULL, result_hex TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE TRIGGER signer_offline_enrollments_no_update BEFORE UPDATE ON signer_offline_enrollments BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_enrollments_no_delete BEFORE DELETE ON signer_offline_enrollments BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_intents_no_update BEFORE UPDATE ON signer_offline_intents BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_intents_no_delete BEFORE DELETE ON signer_offline_intents BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_admissions_no_update BEFORE UPDATE ON signer_offline_admissions BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_admissions_no_delete BEFORE DELETE ON signer_offline_admissions BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_remote_exposures_no_update BEFORE UPDATE ON signer_offline_remote_exposures BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_remote_exposures_no_delete BEFORE DELETE ON signer_offline_remote_exposures BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_remote_inputs_no_update BEFORE UPDATE ON signer_offline_remote_inputs BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_remote_inputs_no_delete BEFORE DELETE ON signer_offline_remote_inputs BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_original_consents_no_update BEFORE UPDATE ON signer_offline_original_consents BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_original_consents_no_delete BEFORE DELETE ON signer_offline_original_consents BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_keyuse_no_update BEFORE UPDATE ON signer_offline_keyuse BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_keyuse_no_delete BEFORE DELETE ON signer_offline_keyuse BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_results_no_update BEFORE UPDATE ON signer_offline_results BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_results_no_delete BEFORE DELETE ON signer_offline_results BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_local_admissions_no_update BEFORE UPDATE ON signer_offline_local_admissions BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_local_admissions_no_delete BEFORE DELETE ON signer_offline_local_admissions BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_local_inputs_no_update BEFORE UPDATE ON signer_offline_local_inputs BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;
CREATE TRIGGER signer_offline_local_inputs_no_delete BEFORE DELETE ON signer_offline_local_inputs BEGIN SELECT RAISE(ABORT,'immutable offline origin history'); END;

-- Proposed additive signer schema. Migration creates EMPTY tables, which reads
-- as UNKNOWN; it must NEVER insert an empty/eligible genesis for a legacy key.
CREATE TABLE signer_account_use_genesis (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 account_id TEXT NOT NULL,
 full_viewing_key_digest TEXT NOT NULL,
 genesis_digest TEXT NOT NULL UNIQUE,
 payload TEXT NOT NULL
);
CREATE TABLE signer_account_use_exclusion (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 genesis_digest TEXT NOT NULL REFERENCES signer_account_use_genesis(genesis_digest),
 exclusion_digest TEXT NOT NULL UNIQUE,
 payload TEXT NOT NULL
);
CREATE TABLE signer_account_use_witness_ack (
 exclusion_digest TEXT PRIMARY KEY REFERENCES signer_account_use_exclusion(exclusion_digest),
 witness_origin_digest TEXT NOT NULL,
 committed_head_digest TEXT NOT NULL,
 receipt_digest TEXT NOT NULL,
 payload TEXT NOT NULL
);
CREATE TRIGGER signer_account_use_genesis_no_update BEFORE UPDATE ON signer_account_use_genesis BEGIN SELECT RAISE(ABORT,'immutable account identity'); END;
CREATE TRIGGER signer_account_use_genesis_no_delete BEFORE DELETE ON signer_account_use_genesis BEGIN SELECT RAISE(ABORT,'immutable account identity'); END;
CREATE TRIGGER signer_account_use_exclusion_no_update BEFORE UPDATE ON signer_account_use_exclusion BEGIN SELECT RAISE(ABORT,'permanent exclusion'); END;
CREATE TRIGGER signer_account_use_exclusion_no_delete BEFORE DELETE ON signer_account_use_exclusion BEGIN SELECT RAISE(ABORT,'permanent exclusion'); END;
CREATE TRIGGER signer_account_use_witness_ack_no_update BEFORE UPDATE ON signer_account_use_witness_ack BEGIN SELECT RAISE(ABORT,'immutable witness acknowledgement'); END;
CREATE TRIGGER signer_account_use_witness_ack_no_delete BEFORE DELETE ON signer_account_use_witness_ack BEGIN SELECT RAISE(ABORT,'immutable witness acknowledgement'); END;

CREATE TRIGGER signer_account_use_genesis_no_replace BEFORE INSERT ON signer_account_use_genesis WHEN EXISTS(SELECT 1 FROM signer_account_use_genesis) BEGIN SELECT RAISE(ABORT,'immutable account-use record'); END;
CREATE TRIGGER signer_account_use_exclusion_no_replace BEFORE INSERT ON signer_account_use_exclusion WHEN EXISTS(SELECT 1 FROM signer_account_use_exclusion) BEGIN SELECT RAISE(ABORT,'immutable account-use record'); END;
CREATE TRIGGER signer_account_use_witness_ack_no_replace BEFORE INSERT ON signer_account_use_witness_ack WHEN EXISTS(SELECT 1 FROM signer_account_use_witness_ack) BEGIN SELECT RAISE(ABORT,'immutable account-use record'); END;
-- Additive proposal AFTER schema v12. Not part of active schema or migration.
CREATE TABLE signer_offline_review_inputs (
 authorization_id TEXT PRIMARY KEY, account_id TEXT NOT NULL,
 terms_digest TEXT NOT NULL, package_digest TEXT NOT NULL,
 envelope_digest TEXT NOT NULL, envelope_hex TEXT NOT NULL
);
CREATE TABLE signer_offline_review_authenticated (
 authorization_id TEXT PRIMARY KEY REFERENCES signer_offline_review_inputs(authorization_id),
 receipt_digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL
);
CREATE TABLE signer_offline_review_accepted (
 authorization_id TEXT PRIMARY KEY REFERENCES signer_offline_review_authenticated(authorization_id),
 receipt_digest TEXT NOT NULL UNIQUE
);
CREATE TRIGGER signer_offline_review_inputs_no_replace BEFORE INSERT ON signer_offline_review_inputs WHEN EXISTS(SELECT 1 FROM signer_offline_review_inputs WHERE authorization_id=NEW.authorization_id) BEGIN SELECT RAISE(ABORT,'immutable offline review receipt'); END;
CREATE TRIGGER signer_offline_review_inputs_no_update BEFORE UPDATE ON signer_offline_review_inputs BEGIN SELECT RAISE(ABORT,'immutable offline review receipt'); END;
CREATE TRIGGER signer_offline_review_inputs_no_delete BEFORE DELETE ON signer_offline_review_inputs BEGIN SELECT RAISE(ABORT,'immutable offline review receipt'); END;
CREATE TRIGGER signer_offline_review_authenticated_no_replace BEFORE INSERT ON signer_offline_review_authenticated WHEN EXISTS(SELECT 1 FROM signer_offline_review_authenticated WHERE authorization_id=NEW.authorization_id) BEGIN SELECT RAISE(ABORT,'immutable offline review receipt'); END;
CREATE TRIGGER signer_offline_review_authenticated_no_update BEFORE UPDATE ON signer_offline_review_authenticated BEGIN SELECT RAISE(ABORT,'immutable offline review receipt'); END;
CREATE TRIGGER signer_offline_review_authenticated_no_delete BEFORE DELETE ON signer_offline_review_authenticated BEGIN SELECT RAISE(ABORT,'immutable offline review receipt'); END;
CREATE TRIGGER signer_offline_review_accepted_no_replace BEFORE INSERT ON signer_offline_review_accepted WHEN EXISTS(SELECT 1 FROM signer_offline_review_accepted WHERE authorization_id=NEW.authorization_id) BEGIN SELECT RAISE(ABORT,'immutable offline review receipt'); END;
CREATE TRIGGER signer_offline_review_accepted_no_update BEFORE UPDATE ON signer_offline_review_accepted BEGIN SELECT RAISE(ABORT,'immutable offline review receipt'); END;
CREATE TRIGGER signer_offline_review_accepted_no_delete BEFORE DELETE ON signer_offline_review_accepted BEGIN SELECT RAISE(ABORT,'immutable offline review receipt'); END;

-- Inert common-context receipts. No row can recreate a process-local owner.
CREATE TABLE signer_common_context_audit_v3 (
 invocation_digest TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN('read_admitted','reserved','consumed')),
 account_id TEXT NOT NULL, receipt_digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL,
 PRIMARY KEY(invocation_digest,phase)
);
CREATE TRIGGER signer_common_context_audit_no_update BEFORE UPDATE ON signer_common_context_audit_v3 BEGIN SELECT RAISE(ABORT,'immutable common-context receipt'); END;
CREATE TRIGGER signer_common_context_audit_no_delete BEFORE DELETE ON signer_common_context_audit_v3 BEGIN SELECT RAISE(ABORT,'immutable common-context receipt'); END;
CREATE TRIGGER signer_common_context_audit_no_replace BEFORE INSERT ON signer_common_context_audit_v3 WHEN EXISTS(SELECT 1 FROM signer_common_context_audit_v3 WHERE invocation_digest=NEW.invocation_digest AND phase=NEW.phase) BEGIN SELECT RAISE(ABORT,'immutable common-context receipt'); END;
-- Explicit old-read/new-construction lineage. Never a restorable owner.
CREATE TABLE signer_common_context_reentry_v1 (
 invocation_digest TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN('authorized','granted','claimed','reentered','reserved','consumed')),
 account_id TEXT NOT NULL, receipt_digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL,
 PRIMARY KEY(invocation_digest,phase)
);
CREATE TRIGGER signer_common_context_reentry_no_update BEFORE UPDATE ON signer_common_context_reentry_v1 BEGIN SELECT RAISE(ABORT,'immutable common-context reentry'); END;
CREATE TRIGGER signer_common_context_reentry_no_delete BEFORE DELETE ON signer_common_context_reentry_v1 BEGIN SELECT RAISE(ABORT,'immutable common-context reentry'); END;
CREATE TRIGGER signer_common_context_reentry_no_replace BEFORE INSERT ON signer_common_context_reentry_v1 WHEN EXISTS(SELECT 1 FROM signer_common_context_reentry_v1 WHERE invocation_digest=NEW.invocation_digest AND phase=NEW.phase) BEGIN SELECT RAISE(ABORT,'immutable common-context reentry'); END;

-- Additive schema16 retention only. No table creates live signing authority.
-- Profile payload contains private transport material and stays inside SQLCipher.
CREATE TABLE signer_named_recipient_profiles (
 reference TEXT PRIMARY KEY NOT NULL, original_setup_digest TEXT NOT NULL UNIQUE,
 account_id TEXT NOT NULL,
 enrollment_ref TEXT NOT NULL REFERENCES signer_enrollments(reference),
 manifest_ref TEXT NOT NULL REFERENCES signer_accepted_manifests(reference),
 payload TEXT NOT NULL
);
CREATE TABLE signer_named_recipient_originals (
 reference TEXT PRIMARY KEY NOT NULL,
 profile_ref TEXT NOT NULL REFERENCES signer_named_recipient_profiles(reference),
 authorization_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL,
 UNIQUE(authorization_id,reference)
);
CREATE TABLE signer_named_recipient_receipts (
 profile_ref TEXT NOT NULL REFERENCES signer_named_recipient_profiles(reference),
 stream TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>0),
 message_id TEXT NOT NULL, content_hash TEXT NOT NULL,
 payload_digest TEXT NOT NULL, envelope_digest TEXT NOT NULL,
 immutable_slot TEXT, envelope_hex TEXT NOT NULL,
 PRIMARY KEY(profile_ref,stream,sequence),
 UNIQUE(profile_ref,stream,message_id), UNIQUE(profile_ref,immutable_slot)
);
CREATE TABLE signer_named_recipient_started (
 authorization_id TEXT PRIMARY KEY NOT NULL REFERENCES signer_named_recipient_originals(authorization_id),
 original_ref TEXT NOT NULL UNIQUE REFERENCES signer_named_recipient_originals(reference),
 marker_digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL,
 FOREIGN KEY(authorization_id,original_ref) REFERENCES signer_named_recipient_originals(authorization_id,reference)
);
CREATE TABLE signer_named_recipient_results (
 authorization_id TEXT PRIMARY KEY NOT NULL REFERENCES signer_named_recipient_started(authorization_id),
 result_digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL
);
CREATE TRIGGER signer_named_recipient_profiles_no_replace BEFORE INSERT ON signer_named_recipient_profiles WHEN EXISTS(SELECT 1 FROM signer_named_recipient_profiles WHERE reference=NEW.reference OR original_setup_digest=NEW.original_setup_digest) BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_profiles_no_update BEFORE UPDATE ON signer_named_recipient_profiles BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_profiles_no_delete BEFORE DELETE ON signer_named_recipient_profiles BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_originals_no_replace BEFORE INSERT ON signer_named_recipient_originals WHEN EXISTS(SELECT 1 FROM signer_named_recipient_originals WHERE reference=NEW.reference OR authorization_id=NEW.authorization_id) BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_originals_no_update BEFORE UPDATE ON signer_named_recipient_originals BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_originals_no_delete BEFORE DELETE ON signer_named_recipient_originals BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_receipts_no_replace BEFORE INSERT ON signer_named_recipient_receipts WHEN EXISTS(SELECT 1 FROM signer_named_recipient_receipts WHERE profile_ref=NEW.profile_ref AND ((stream=NEW.stream AND (sequence=NEW.sequence OR message_id=NEW.message_id)) OR (immutable_slot IS NOT NULL AND immutable_slot=NEW.immutable_slot))) BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_receipts_no_update BEFORE UPDATE ON signer_named_recipient_receipts BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_receipts_no_delete BEFORE DELETE ON signer_named_recipient_receipts BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_started_no_replace BEFORE INSERT ON signer_named_recipient_started WHEN EXISTS(SELECT 1 FROM signer_named_recipient_started WHERE authorization_id=NEW.authorization_id OR original_ref=NEW.original_ref OR marker_digest=NEW.marker_digest) BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_started_no_update BEFORE UPDATE ON signer_named_recipient_started BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_started_no_delete BEFORE DELETE ON signer_named_recipient_started BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_results_no_replace BEFORE INSERT ON signer_named_recipient_results WHEN EXISTS(SELECT 1 FROM signer_named_recipient_results WHERE authorization_id=NEW.authorization_id OR result_digest=NEW.result_digest) BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_results_no_update BEFORE UPDATE ON signer_named_recipient_results BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_results_no_delete BEFORE DELETE ON signer_named_recipient_results BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;

-- Additive proposal for the still-unpublished signer schema16. It is not yet
-- registered or qualified. The exact original payload retains request/template.
CREATE TABLE signer_named_intent_outbox (
 authorization_id TEXT PRIMARY KEY NOT NULL REFERENCES signer_named_recipient_originals(authorization_id),
 original_ref TEXT NOT NULL UNIQUE REFERENCES signer_named_recipient_originals(reference),
 profile_ref TEXT NOT NULL REFERENCES signer_named_recipient_profiles(reference),
 stream TEXT NOT NULL,
 sequence INTEGER NOT NULL CHECK(sequence>0),
 message_id TEXT NOT NULL,
 content_hash TEXT NOT NULL,
 payload_digest TEXT NOT NULL,
 envelope_digest TEXT NOT NULL,
 preview_json TEXT NOT NULL,
 envelope_hex TEXT NOT NULL,
 UNIQUE(profile_ref,stream,sequence),
 UNIQUE(profile_ref,stream,message_id),
 FOREIGN KEY(authorization_id,original_ref) REFERENCES signer_named_recipient_originals(authorization_id,reference)
);
CREATE TRIGGER signer_named_intent_outbox_no_update BEFORE UPDATE ON signer_named_intent_outbox BEGIN SELECT RAISE(ABORT,'immutable named intent outbox'); END;
CREATE TRIGGER signer_named_intent_outbox_no_delete BEFORE DELETE ON signer_named_intent_outbox BEGIN SELECT RAISE(ABORT,'immutable named intent outbox'); END;
CREATE TRIGGER signer_named_intent_outbox_no_replace BEFORE INSERT ON signer_named_intent_outbox WHEN EXISTS(
 SELECT 1 FROM signer_named_intent_outbox WHERE authorization_id=NEW.authorization_id OR original_ref=NEW.original_ref OR (profile_ref=NEW.profile_ref AND stream=NEW.stream AND (sequence=NEW.sequence OR message_id=NEW.message_id))
) BEGIN SELECT RAISE(ABORT,'immutable named intent outbox'); END;

-- Purpose-distinct immutable local intent, retained before born witness dispatch.
CREATE TABLE signer_named_recipient_dispatch_requests (
 operation_id TEXT PRIMARY KEY NOT NULL,
 authorization_id TEXT NOT NULL REFERENCES signer_named_recipient_results(authorization_id),
 original_ref TEXT NOT NULL REFERENCES signer_named_recipient_originals(reference),
 request_digest TEXT NOT NULL UNIQUE,
 payload TEXT NOT NULL,
 FOREIGN KEY(authorization_id,original_ref) REFERENCES signer_named_recipient_originals(authorization_id,reference)
);
CREATE TRIGGER signer_named_recipient_dispatch_no_update BEFORE UPDATE ON signer_named_recipient_dispatch_requests BEGIN SELECT RAISE(ABORT,'immutable born dispatch intent'); END;
CREATE TRIGGER signer_named_recipient_dispatch_no_delete BEFORE DELETE ON signer_named_recipient_dispatch_requests BEGIN SELECT RAISE(ABORT,'immutable born dispatch intent'); END;
CREATE TRIGGER signer_named_recipient_dispatch_no_replace BEFORE INSERT ON signer_named_recipient_dispatch_requests WHEN EXISTS(SELECT 1 FROM signer_named_recipient_dispatch_requests WHERE operation_id=NEW.operation_id OR request_digest=NEW.request_digest) BEGIN SELECT RAISE(ABORT,'immutable born dispatch intent'); END;
