-- Explicit old-read/new-construction lineage. Never a restorable owner.
CREATE TABLE signer_common_context_reentry_v1 (
 invocation_digest TEXT NOT NULL, phase TEXT NOT NULL CHECK(phase IN('authorized','granted','claimed','reentered','reserved','consumed')),
 account_id TEXT NOT NULL, receipt_digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL,
 PRIMARY KEY(invocation_digest,phase)
);
CREATE TRIGGER signer_common_context_reentry_no_update BEFORE UPDATE ON signer_common_context_reentry_v1 BEGIN SELECT RAISE(ABORT,'immutable common-context reentry'); END;
CREATE TRIGGER signer_common_context_reentry_no_delete BEFORE DELETE ON signer_common_context_reentry_v1 BEGIN SELECT RAISE(ABORT,'immutable common-context reentry'); END;
CREATE TRIGGER signer_common_context_reentry_no_replace BEFORE INSERT ON signer_common_context_reentry_v1 WHEN EXISTS(SELECT 1 FROM signer_common_context_reentry_v1 WHERE invocation_digest=NEW.invocation_digest AND phase=NEW.phase) BEGIN SELECT RAISE(ABORT,'immutable common-context reentry'); END;
