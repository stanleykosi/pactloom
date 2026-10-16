-- Proposed additive signer schema. Migration creates EMPTY tables, which reads
-- as UNKNOWN; it must NEVER insert an empty/eligible genesis for a legacy key.
CREATE TABLE signer_account_use_genesis (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 account_id TEXT NOT NULL,
 full_viewing_key_digest TEXT NOT NULL,
 genesis_digest TEXT NOT NULL UNIQUE,
 payload TEXT NOT NULL
);
CREATE TABLE signer_account_use_exclusion (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 genesis_digest TEXT NOT NULL REFERENCES signer_account_use_genesis(genesis_digest),
 exclusion_digest TEXT NOT NULL UNIQUE,
 payload TEXT NOT NULL
);
CREATE TABLE signer_account_use_witness_ack (
 exclusion_digest TEXT PRIMARY KEY REFERENCES signer_account_use_exclusion(exclusion_digest),
 witness_origin_digest TEXT NOT NULL,
 committed_head_digest TEXT NOT NULL,
 receipt_digest TEXT NOT NULL,
 payload TEXT NOT NULL
);
CREATE TRIGGER signer_account_use_genesis_no_update BEFORE UPDATE ON signer_account_use_genesis BEGIN SELECT RAISE(ABORT,'immutable account identity'); END;
CREATE TRIGGER signer_account_use_genesis_no_delete BEFORE DELETE ON signer_account_use_genesis BEGIN SELECT RAISE(ABORT,'immutable account identity'); END;
CREATE TRIGGER signer_account_use_exclusion_no_update BEFORE UPDATE ON signer_account_use_exclusion BEGIN SELECT RAISE(ABORT,'permanent exclusion'); END;
CREATE TRIGGER signer_account_use_exclusion_no_delete BEFORE DELETE ON signer_account_use_exclusion BEGIN SELECT RAISE(ABORT,'permanent exclusion'); END;
CREATE TRIGGER signer_account_use_witness_ack_no_update BEFORE UPDATE ON signer_account_use_witness_ack BEGIN SELECT RAISE(ABORT,'immutable witness acknowledgement'); END;
CREATE TRIGGER signer_account_use_witness_ack_no_delete BEFORE DELETE ON signer_account_use_witness_ack BEGIN SELECT RAISE(ABORT,'immutable witness acknowledgement'); END;

CREATE TRIGGER signer_account_use_genesis_no_replace BEFORE INSERT ON signer_account_use_genesis WHEN EXISTS(SELECT 1 FROM signer_account_use_genesis) BEGIN SELECT RAISE(ABORT,'immutable account-use record'); END;
CREATE TRIGGER signer_account_use_exclusion_no_replace BEFORE INSERT ON signer_account_use_exclusion WHEN EXISTS(SELECT 1 FROM signer_account_use_exclusion) BEGIN SELECT RAISE(ABORT,'immutable account-use record'); END;
CREATE TRIGGER signer_account_use_witness_ack_no_replace BEFORE INSERT ON signer_account_use_witness_ack WHEN EXISTS(SELECT 1 FROM signer_account_use_witness_ack) BEGIN SELECT RAISE(ABORT,'immutable account-use record'); END;
