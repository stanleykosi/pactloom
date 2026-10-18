-- Immutable historical financial admission intent. This is not a reservation,
-- live consent, financial serving permission, or an owner-control outbox.
CREATE TABLE signer_durable_payment_admission_intents (
 operation_id TEXT PRIMARY KEY NOT NULL,
 authorization_id TEXT NOT NULL UNIQUE,
 request_digest TEXT NOT NULL UNIQUE,
 enrollment_ref TEXT NOT NULL REFERENCES signer_enrollments(reference),
 manifest_ref TEXT NOT NULL REFERENCES signer_accepted_manifests(reference),
 payload TEXT NOT NULL
);
CREATE TRIGGER signer_durable_payment_admission_intents_no_update BEFORE UPDATE ON signer_durable_payment_admission_intents BEGIN SELECT RAISE(ABORT,'immutable financial admission intent'); END;
CREATE TRIGGER signer_durable_payment_admission_intents_no_delete BEFORE DELETE ON signer_durable_payment_admission_intents BEGIN SELECT RAISE(ABORT,'immutable financial admission intent'); END;
CREATE TRIGGER signer_durable_payment_admission_intents_no_replace BEFORE INSERT ON signer_durable_payment_admission_intents WHEN EXISTS(SELECT 1 FROM signer_durable_payment_admission_intents WHERE operation_id=NEW.operation_id OR authorization_id=NEW.authorization_id OR request_digest=NEW.request_digest) BEGIN SELECT RAISE(ABORT,'immutable financial admission intent'); END;
