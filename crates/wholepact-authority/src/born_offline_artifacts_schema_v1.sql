-- Native final approval installs this singleton and the canonical inbox/outbox
-- atomically in the ORIGINAL encrypted authority journal. No additional files.
CREATE TABLE authority_born_offline_artifacts (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 payload BLOB NOT NULL CHECK(length(payload)>0 AND length(payload)<=262144),
 secret BLOB NOT NULL CHECK(length(secret)=32)
) STRICT;
CREATE TRIGGER born_artifacts_no_replace BEFORE INSERT ON authority_born_offline_artifacts WHEN EXISTS(SELECT 1 FROM authority_born_offline_artifacts) BEGIN SELECT RAISE(ABORT,'immutable born transport installation'); END;
CREATE TRIGGER born_artifacts_no_update BEFORE UPDATE ON authority_born_offline_artifacts BEGIN SELECT RAISE(ABORT,'immutable born transport installation'); END;
CREATE TRIGGER born_artifacts_no_delete BEFORE DELETE ON authority_born_offline_artifacts BEGIN SELECT RAISE(ABORT,'retained born transport installation'); END;
