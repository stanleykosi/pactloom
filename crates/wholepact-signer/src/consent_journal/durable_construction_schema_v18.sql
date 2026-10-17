-- Data-only exact native construction disclosure. No spending authority.
CREATE TABLE signer_durable_construction_outbox (
 operation_id TEXT PRIMARY KEY NOT NULL,
 request_digest TEXT NOT NULL UNIQUE,
 enrollment_ref TEXT NOT NULL REFERENCES signer_enrollments(reference),
 manifest_ref TEXT NOT NULL REFERENCES signer_accepted_manifests(reference),
 payload TEXT NOT NULL
);
CREATE TRIGGER signer_durable_construction_outbox_no_update BEFORE UPDATE ON signer_durable_construction_outbox BEGIN SELECT RAISE(ABORT,'immutable durable construction disclosure'); END;
CREATE TRIGGER signer_durable_construction_outbox_no_delete BEFORE DELETE ON signer_durable_construction_outbox BEGIN SELECT RAISE(ABORT,'immutable durable construction disclosure'); END;
CREATE TRIGGER signer_durable_construction_outbox_no_replace BEFORE INSERT ON signer_durable_construction_outbox WHEN EXISTS(SELECT 1 FROM signer_durable_construction_outbox WHERE operation_id=NEW.operation_id OR request_digest=NEW.request_digest) BEGIN SELECT RAISE(ABORT,'immutable durable construction disclosure'); END;
