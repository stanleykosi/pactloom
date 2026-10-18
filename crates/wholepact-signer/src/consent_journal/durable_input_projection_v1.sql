-- Inactive additive schema leaf. Install only with the parent-owned migration,
-- exact schema verification, complete capacity/backup inventory and typed reads.
-- A committed row means disclosure happened or may have happened, forever.
CREATE TABLE signer_durable_input_projection_outbox_v1 (
 operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 128),
 request_digest TEXT NOT NULL UNIQUE CHECK(length(request_digest)=64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
 reference TEXT NOT NULL UNIQUE CHECK(length(reference)=64 AND reference NOT GLOB '*[^0-9a-f]*'),
 account_id TEXT NOT NULL CHECK(length(account_id)=64 AND account_id NOT GLOB '*[^0-9a-f]*'),
 genesis_digest TEXT NOT NULL REFERENCES signer_account_use_genesis(genesis_digest) CHECK(length(genesis_digest)=64 AND genesis_digest NOT GLOB '*[^0-9a-f]*'),
 source_digest TEXT NOT NULL CHECK(length(source_digest)=64 AND source_digest NOT GLOB '*[^0-9a-f]*'),
 payload TEXT NOT NULL CHECK(length(CAST(payload AS BLOB)) BETWEEN 1 AND 131071),
 source_payload TEXT NOT NULL CHECK(length(CAST(source_payload AS BLOB)) BETWEEN 1 AND 524288)
);
CREATE TABLE signer_durable_input_projection_deliveries_v1 (
 operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 128),
 request_digest TEXT NOT NULL UNIQUE CHECK(length(request_digest)=64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
 reference TEXT NOT NULL UNIQUE CHECK(length(reference)=64 AND reference NOT GLOB '*[^0-9a-f]*'),
 original_operation_id TEXT NOT NULL REFERENCES signer_durable_input_projection_outbox_v1(operation_id),
 original_request_digest TEXT NOT NULL CHECK(length(original_request_digest)=64 AND original_request_digest NOT GLOB '*[^0-9a-f]*'),
 original_outbox_reference TEXT NOT NULL CHECK(length(original_outbox_reference)=64 AND original_outbox_reference NOT GLOB '*[^0-9a-f]*'),
 recipient_digest TEXT NOT NULL CHECK(length(recipient_digest)=64 AND recipient_digest NOT GLOB '*[^0-9a-f]*'),
 payload TEXT NOT NULL CHECK(length(CAST(payload AS BLOB)) BETWEEN 1 AND 131071),
 CHECK(operation_id <> original_operation_id)
);
CREATE TRIGGER signer_durable_input_projection_outbox_v1_no_update
 BEFORE UPDATE ON signer_durable_input_projection_outbox_v1
 BEGIN SELECT RAISE(ABORT,'immutable input projection disclosure'); END;
CREATE TRIGGER signer_durable_input_projection_outbox_v1_no_delete
 BEFORE DELETE ON signer_durable_input_projection_outbox_v1
 BEGIN SELECT RAISE(ABORT,'immutable input projection disclosure'); END;
CREATE TRIGGER signer_durable_input_projection_outbox_v1_no_replace
 BEFORE INSERT ON signer_durable_input_projection_outbox_v1
 WHEN EXISTS(SELECT 1 FROM signer_durable_input_projection_outbox_v1
             WHERE operation_id=NEW.operation_id OR request_digest=NEW.request_digest OR reference=NEW.reference)
   OR EXISTS(SELECT 1 FROM signer_durable_input_projection_deliveries_v1 WHERE operation_id=NEW.operation_id)
 BEGIN SELECT RAISE(ABORT,'immutable input projection disclosure'); END;
CREATE TRIGGER signer_durable_input_projection_deliveries_v1_no_update
 BEFORE UPDATE ON signer_durable_input_projection_deliveries_v1
 BEGIN SELECT RAISE(ABORT,'immutable input projection redelivery'); END;
CREATE TRIGGER signer_durable_input_projection_deliveries_v1_no_delete
 BEFORE DELETE ON signer_durable_input_projection_deliveries_v1
 BEGIN SELECT RAISE(ABORT,'immutable input projection redelivery'); END;
CREATE TRIGGER signer_durable_input_projection_deliveries_v1_no_replace
 BEFORE INSERT ON signer_durable_input_projection_deliveries_v1
 WHEN EXISTS(SELECT 1 FROM signer_durable_input_projection_deliveries_v1
             WHERE operation_id=NEW.operation_id OR request_digest=NEW.request_digest OR reference=NEW.reference)
   OR EXISTS(SELECT 1 FROM signer_durable_input_projection_outbox_v1 WHERE operation_id=NEW.operation_id)
 BEGIN SELECT RAISE(ABORT,'immutable input projection redelivery'); END;
-- The native typed writer also checks this exact link. Keeping the structural
-- conjunction in SQL makes restoration refuse a mismatched source immediately.
CREATE TRIGGER signer_durable_input_projection_deliveries_v1_exact_original
 BEFORE INSERT ON signer_durable_input_projection_deliveries_v1
 WHEN NOT EXISTS(SELECT 1 FROM signer_durable_input_projection_outbox_v1
                 WHERE operation_id=NEW.original_operation_id
                   AND request_digest=NEW.original_request_digest
                   AND reference=NEW.original_outbox_reference)
 BEGIN SELECT RAISE(ABORT,'input projection original link mismatch'); END;
