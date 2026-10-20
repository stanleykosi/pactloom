-- Explicit original-only financial continuation. The original schema19
-- admission row remains immutable and keeps its original authorization ID.
CREATE TABLE signer_financial_continuation_intents (
 operation_id TEXT PRIMARY KEY NOT NULL,
 authorization_id TEXT NOT NULL UNIQUE REFERENCES signer_durable_payment_admission_intents(authorization_id),
 original_admission_operation_id TEXT NOT NULL UNIQUE REFERENCES signer_durable_payment_admission_intents(operation_id),
 request_digest TEXT NOT NULL UNIQUE,
 enrollment_ref TEXT NOT NULL REFERENCES signer_enrollments(reference),
 manifest_ref TEXT NOT NULL REFERENCES signer_accepted_manifests(reference),
 payload TEXT NOT NULL
);
CREATE TRIGGER signer_financial_continuation_intents_no_update BEFORE UPDATE ON signer_financial_continuation_intents BEGIN SELECT RAISE(ABORT,'immutable financial continuation intent'); END;
CREATE TRIGGER signer_financial_continuation_intents_no_delete BEFORE DELETE ON signer_financial_continuation_intents BEGIN SELECT RAISE(ABORT,'immutable financial continuation intent'); END;
CREATE TRIGGER signer_financial_continuation_intents_no_replace BEFORE INSERT ON signer_financial_continuation_intents WHEN EXISTS(SELECT 1 FROM signer_financial_continuation_intents WHERE operation_id=NEW.operation_id OR authorization_id=NEW.authorization_id OR original_admission_operation_id=NEW.original_admission_operation_id OR request_digest=NEW.request_digest) BEGIN SELECT RAISE(ABORT,'immutable financial continuation intent'); END;
