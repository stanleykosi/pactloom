-- Inert common-context receipts. No row can recreate a process-local owner.
CREATE TABLE signer_common_context_audit_v3 (
 invocation_digest TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN('read_admitted','reserved','consumed')),
 account_id TEXT NOT NULL, receipt_digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL,
 PRIMARY KEY(invocation_digest,phase)
);
CREATE TRIGGER signer_common_context_audit_no_update BEFORE UPDATE ON signer_common_context_audit_v3 BEGIN SELECT RAISE(ABORT,'immutable common-context receipt'); END;
CREATE TRIGGER signer_common_context_audit_no_delete BEFORE DELETE ON signer_common_context_audit_v3 BEGIN SELECT RAISE(ABORT,'immutable common-context receipt'); END;
CREATE TRIGGER signer_common_context_audit_no_replace BEFORE INSERT ON signer_common_context_audit_v3 WHEN EXISTS(SELECT 1 FROM signer_common_context_audit_v3 WHERE invocation_digest=NEW.invocation_digest AND phase=NEW.phase) BEGIN SELECT RAISE(ABORT,'immutable common-context receipt'); END;
