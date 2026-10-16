CREATE TABLE authority_genesis (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), policy BLOB NOT NULL,
 CHECK(length(policy)>0 AND length(policy)<=262144)
);
CREATE TABLE authority_events (
 sequence INTEGER PRIMARY KEY CHECK(sequence>0 AND sequence<=10000),
 operation_id TEXT NOT NULL UNIQUE,
 previous_head TEXT NOT NULL CHECK(length(previous_head)=64),
 head TEXT NOT NULL UNIQUE CHECK(length(head)=64),
 payload BLOB NOT NULL CHECK(length(payload)>0 AND length(payload)<=262144)
);
CREATE TABLE authority_quarantine (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), quarantined INTEGER NOT NULL CHECK(quarantined IN(0,1))
);
CREATE TABLE authority_principals (
 certificate_digest TEXT PRIMARY KEY CHECK(length(certificate_digest)=64)
);
CREATE TRIGGER genesis_no_update BEFORE UPDATE ON authority_genesis BEGIN SELECT RAISE(ABORT,'immutable owner enrollment'); END;
CREATE TRIGGER genesis_no_delete BEFORE DELETE ON authority_genesis BEGIN SELECT RAISE(ABORT,'immutable owner enrollment'); END;
CREATE TRIGGER events_no_update BEFORE UPDATE ON authority_events BEGIN SELECT RAISE(ABORT,'immutable reservation history'); END;
CREATE TRIGGER events_no_delete BEFORE DELETE ON authority_events BEGIN SELECT RAISE(ABORT,'immutable reservation history'); END;
CREATE TRIGGER quarantine_monotone BEFORE UPDATE ON authority_quarantine WHEN OLD.quarantined=1 AND NEW.quarantined!=1 BEGIN SELECT RAISE(ABORT,'restored authority cannot be reactivated'); END;
CREATE TRIGGER quarantine_no_delete BEFORE DELETE ON authority_quarantine BEGIN SELECT RAISE(ABORT,'authority safety state cannot be removed'); END;
CREATE TRIGGER principals_no_update BEFORE UPDATE ON authority_principals BEGIN SELECT RAISE(ABORT,'retained admission identity'); END;
CREATE TRIGGER principals_no_delete BEFORE DELETE ON authority_principals BEGIN SELECT RAISE(ABORT,'retained admission identity'); END;

CREATE TABLE authority_session_keys (session_id TEXT PRIMARY KEY CHECK(length(session_id)=64), secret BLOB NOT NULL CHECK(length(secret)=32));
CREATE TRIGGER session_keys_no_update BEFORE UPDATE ON authority_session_keys BEGIN SELECT RAISE(ABORT,'immutable writer session'); END;
CREATE TRIGGER session_keys_no_delete BEFORE DELETE ON authority_session_keys BEGIN SELECT RAISE(ABORT,'retained writer session'); END;

CREATE TABLE authority_resolution_evidence (evidence_digest TEXT PRIMARY KEY CHECK(length(evidence_digest)=64), payload BLOB NOT NULL CHECK(length(payload)>0 AND length(payload)<=262144));
CREATE TRIGGER resolution_evidence_no_update BEFORE UPDATE ON authority_resolution_evidence BEGIN SELECT RAISE(ABORT,'immutable canonical evidence'); END;
CREATE TRIGGER resolution_evidence_no_delete BEFORE DELETE ON authority_resolution_evidence BEGIN SELECT RAISE(ABORT,'retained canonical evidence'); END;
