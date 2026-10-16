-- Version-four additions, installed only by checked migration or encrypted creation.
-- Both tables live in the AuthorityJournal's concrete EncryptedConnection.
CREATE TABLE authority_offline_originals (
 operation_id TEXT PRIMARY KEY CHECK(length(operation_id)>0 AND length(operation_id)<=128),
 intent_id TEXT NOT NULL UNIQUE CHECK(length(intent_id)>0 AND length(intent_id)<=128),
 intent_digest TEXT NOT NULL UNIQUE CHECK(length(intent_digest)=64),
 authorization_id TEXT NOT NULL UNIQUE CHECK(length(authorization_id)>0 AND length(authorization_id)<=128),
 prepared_digest TEXT NOT NULL UNIQUE CHECK(length(prepared_digest)=64),
 request_digest TEXT NOT NULL UNIQUE CHECK(length(request_digest)=64),
 envelope_digest TEXT NOT NULL UNIQUE CHECK(length(envelope_digest)=64),
 payload BLOB NOT NULL CHECK(length(payload)>0 AND length(payload)<=262144),
 envelope BLOB NOT NULL CHECK(length(envelope)>0 AND length(envelope)<=1048576)
);
CREATE TABLE authority_offline_original_receipts (
 prepared_digest TEXT PRIMARY KEY REFERENCES authority_offline_originals(prepared_digest),
 receipt_digest TEXT NOT NULL UNIQUE CHECK(length(receipt_digest)=64),
 original_stream TEXT NOT NULL CHECK(length(original_stream)=64),
 original_sequence INTEGER NOT NULL CHECK(original_sequence>0),
 original_message_id TEXT NOT NULL CHECK(length(original_message_id)=32),
 export_stream TEXT NOT NULL CHECK(length(export_stream)=64),
 export_sequence INTEGER NOT NULL CHECK(export_sequence>0),
 export_message_id TEXT NOT NULL CHECK(length(export_message_id)=32),
 payload BLOB NOT NULL CHECK(length(payload)>0 AND length(payload)<=16384),
 UNIQUE(original_stream,original_sequence), UNIQUE(original_stream,original_message_id),
 UNIQUE(export_stream,export_sequence), UNIQUE(export_stream,export_message_id)
);
CREATE TRIGGER offline_original_no_update BEFORE UPDATE ON authority_offline_originals BEGIN SELECT RAISE(ABORT,'immutable original offline request'); END;
CREATE TRIGGER offline_original_no_delete BEFORE DELETE ON authority_offline_originals BEGIN SELECT RAISE(ABORT,'retained original offline request'); END;
CREATE TRIGGER offline_receipt_no_update BEFORE UPDATE ON authority_offline_original_receipts BEGIN SELECT RAISE(ABORT,'immutable authenticated original receipt'); END;
CREATE TRIGGER offline_receipt_no_delete BEFORE DELETE ON authority_offline_original_receipts BEGIN SELECT RAISE(ABORT,'retained authenticated original receipt'); END;

CREATE TABLE authority_offline_inbox_acceptances (
 prepared_digest TEXT PRIMARY KEY REFERENCES authority_offline_original_receipts(prepared_digest),
 acceptance_digest TEXT NOT NULL UNIQUE CHECK(length(acceptance_digest)=64),
 payload BLOB NOT NULL CHECK(length(payload)>0 AND length(payload)<=16384)
);
CREATE TRIGGER offline_inbox_no_update BEFORE UPDATE ON authority_offline_inbox_acceptances BEGIN SELECT RAISE(ABORT,'immutable actual inbox acceptance'); END;
CREATE TRIGGER offline_inbox_no_delete BEFORE DELETE ON authority_offline_inbox_acceptances BEGIN SELECT RAISE(ABORT,'retained actual inbox acceptance'); END;
