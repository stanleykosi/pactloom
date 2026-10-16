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
