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
