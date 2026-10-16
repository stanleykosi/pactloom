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
