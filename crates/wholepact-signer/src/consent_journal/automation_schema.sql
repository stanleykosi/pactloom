
-- Native-approved automation history is audit evidence, never an imported capability.
CREATE TABLE signer_automation_grant_events (
 grant_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0),
 enrollment_ref TEXT NOT NULL REFERENCES signer_enrollments(reference), payload TEXT NOT NULL,
 PRIMARY KEY(grant_id,revision)
);
CREATE TRIGGER signer_automation_grants_no_update BEFORE UPDATE ON signer_automation_grant_events BEGIN SELECT RAISE(ABORT,'immutable native automation grant'); END;
CREATE TRIGGER signer_automation_grants_no_delete BEFORE DELETE ON signer_automation_grant_events BEGIN SELECT RAISE(ABORT,'immutable native automation grant'); END;

CREATE TABLE signer_automation_keyuse (
 authorization_id TEXT PRIMARY KEY REFERENCES signer_bridge_keyuse(authorization_id), payload TEXT NOT NULL
);
CREATE TRIGGER signer_automation_keyuse_no_update BEFORE UPDATE ON signer_automation_keyuse BEGIN SELECT RAISE(ABORT,'immutable automatic key-use admission'); END;
CREATE TRIGGER signer_automation_keyuse_no_delete BEFORE DELETE ON signer_automation_keyuse BEGIN SELECT RAISE(ABORT,'immutable automatic key-use admission'); END;
