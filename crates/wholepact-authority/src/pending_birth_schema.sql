-- UNINTEGRATED. Version must be allocated against the next authority schema.
-- Empty legacy migration means unknown, never synthesize a birth record.
-- Insert only in the same transaction as the genuine approved new genesis.
CREATE TABLE authority_pending_birth_commit (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    operation_id TEXT NOT NULL UNIQUE CHECK(length(operation_id) BETWEEN 1 AND 128),
    request_digest TEXT NOT NULL UNIQUE CHECK(length(request_digest)=64),
    payload TEXT NOT NULL CHECK(length(CAST(payload AS BLOB)) BETWEEN 1 AND 262144)
) STRICT;
CREATE TRIGGER authority_pending_birth_commit_no_replace
BEFORE INSERT ON authority_pending_birth_commit
WHEN EXISTS(SELECT 1 FROM authority_pending_birth_commit)
BEGIN SELECT RAISE(ABORT, 'immutable pending birth commit'); END;
CREATE TRIGGER authority_pending_birth_commit_no_update
BEFORE UPDATE ON authority_pending_birth_commit
BEGIN SELECT RAISE(ABORT, 'immutable pending birth commit'); END;
CREATE TRIGGER authority_pending_birth_commit_no_delete
BEFORE DELETE ON authority_pending_birth_commit
BEGIN SELECT RAISE(ABORT, 'immutable pending birth commit'); END;
