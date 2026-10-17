
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
