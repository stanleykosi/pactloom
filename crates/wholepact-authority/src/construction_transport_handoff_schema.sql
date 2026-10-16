CREATE TABLE authority_construction_transport_grants (
 grant_digest TEXT PRIMARY KEY CHECK(length(grant_digest)=64),
 session_id TEXT NOT NULL UNIQUE CHECK(length(session_id)=64),
 invocation_digest TEXT NOT NULL UNIQUE CHECK(length(invocation_digest)=64),
 read_request_digest TEXT NOT NULL UNIQUE CHECK(length(read_request_digest)=64),
 nonce TEXT NOT NULL UNIQUE CHECK(length(nonce)=64),
 payload BLOB NOT NULL CHECK(length(payload)>0 AND length(payload)<=16384)
);
CREATE TABLE authority_construction_transport_credentials (
 credential_id TEXT PRIMARY KEY CHECK(length(credential_id)=64),
 grant_digest TEXT NOT NULL UNIQUE CHECK(length(grant_digest)=64),
 secret BLOB NOT NULL CHECK(length(secret)=32),
 payload BLOB NOT NULL CHECK(length(payload)>0 AND length(payload)<=32768)
);
CREATE TABLE authority_transport_fences (
 session_id TEXT PRIMARY KEY CHECK(length(session_id)=64),
 credential_id TEXT NOT NULL UNIQUE CHECK(length(credential_id)=64),
 fence_digest TEXT NOT NULL UNIQUE CHECK(length(fence_digest)=64)
);
CREATE TRIGGER construction_grants_no_replace BEFORE INSERT ON authority_construction_transport_grants WHEN EXISTS(SELECT 1 FROM authority_construction_transport_grants WHERE grant_digest=NEW.grant_digest OR session_id=NEW.session_id OR invocation_digest=NEW.invocation_digest OR read_request_digest=NEW.read_request_digest OR nonce=NEW.nonce) BEGIN SELECT RAISE(ABORT,'one immutable construction grant'); END;
CREATE TRIGGER construction_grants_no_update BEFORE UPDATE ON authority_construction_transport_grants BEGIN SELECT RAISE(ABORT,'immutable construction grant'); END;
CREATE TRIGGER construction_grants_no_delete BEFORE DELETE ON authority_construction_transport_grants BEGIN SELECT RAISE(ABORT,'retained construction grant'); END;
CREATE TRIGGER construction_credentials_no_replace BEFORE INSERT ON authority_construction_transport_credentials WHEN EXISTS(SELECT 1 FROM authority_construction_transport_credentials WHERE credential_id=NEW.credential_id OR grant_digest=NEW.grant_digest) BEGIN SELECT RAISE(ABORT,'one immutable construction credential'); END;
CREATE TRIGGER construction_credentials_no_update BEFORE UPDATE ON authority_construction_transport_credentials BEGIN SELECT RAISE(ABORT,'immutable construction credential'); END;
CREATE TRIGGER construction_credentials_no_delete BEFORE DELETE ON authority_construction_transport_credentials BEGIN SELECT RAISE(ABORT,'retained construction credential'); END;
CREATE TRIGGER transport_fences_no_replace BEFORE INSERT ON authority_transport_fences WHEN EXISTS(SELECT 1 FROM authority_transport_fences WHERE session_id=NEW.session_id OR credential_id=NEW.credential_id OR fence_digest=NEW.fence_digest) BEGIN SELECT RAISE(ABORT,'permanent transport fence'); END;
CREATE TRIGGER transport_fences_no_update BEFORE UPDATE ON authority_transport_fences BEGIN SELECT RAISE(ABORT,'permanent transport fence'); END;
CREATE TRIGGER transport_fences_no_delete BEFORE DELETE ON authority_transport_fences BEGIN SELECT RAISE(ABORT,'permanent transport fence'); END;
CREATE TRIGGER handoff_retained_session_keys_no_replace BEFORE INSERT ON authority_session_keys WHEN EXISTS(SELECT 1 FROM authority_session_keys WHERE session_id=NEW.session_id) BEGIN SELECT RAISE(ABORT,'original writer key is immutable'); END;
CREATE TRIGGER handoff_retained_events_no_replace BEFORE INSERT ON authority_events WHEN EXISTS(SELECT 1 FROM authority_events WHERE sequence=NEW.sequence OR operation_id=NEW.operation_id OR head=NEW.head) BEGIN SELECT RAISE(ABORT,'original authority history is immutable'); END;
