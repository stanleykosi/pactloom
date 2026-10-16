-- UNINTEGRATED dedicated encrypted locator, not an authority-journal migration.
-- Installing these tables does NOT prove a canonical namespace was established.
-- Production has no initializer. Only a future native origin-registry owner may
-- perform first installation. Missing/legacy/restored metadata remains denied.
CREATE TABLE witness_locator_namespace (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 binding_digest TEXT NOT NULL UNIQUE CHECK(length(binding_digest)=64),
 payload BLOB NOT NULL CHECK(length(payload)>0 AND length(payload)<=16384)
) STRICT;
CREATE TABLE witness_locator_quarantine (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 quarantined INTEGER NOT NULL CHECK(quarantined IN (0,1))
) STRICT;
CREATE TABLE witness_locator_intents (
 intent_digest TEXT PRIMARY KEY NOT NULL CHECK(length(intent_digest)=64),
 namespace_digest TEXT NOT NULL REFERENCES witness_locator_namespace(binding_digest),
 account_id TEXT NOT NULL UNIQUE CHECK(length(account_id)=64),
 full_viewing_key_digest TEXT NOT NULL UNIQUE CHECK(length(full_viewing_key_digest)=64),
 network_profile_id TEXT NOT NULL CHECK(length(network_profile_id) BETWEEN 1 AND 128),
 derivation_domain TEXT NOT NULL CHECK(length(derivation_domain) BETWEEN 1 AND 128),
 generation_instance_id TEXT NOT NULL UNIQUE CHECK(length(generation_instance_id)=64),
 operation_id TEXT NOT NULL UNIQUE CHECK(length(operation_id) BETWEEN 1 AND 128),
 request_digest TEXT NOT NULL UNIQUE CHECK(length(request_digest)=64),
 derived_child TEXT NOT NULL UNIQUE CHECK(length(derived_child)=76),
 local_target_digest TEXT NOT NULL UNIQUE CHECK(length(local_target_digest)=64),
 payload BLOB NOT NULL CHECK(length(payload)>0 AND length(payload)<=262144)
) STRICT;
CREATE TABLE witness_locator_completions (
 intent_digest TEXT PRIMARY KEY NOT NULL REFERENCES witness_locator_intents(intent_digest),
 genesis_commitment TEXT NOT NULL UNIQUE CHECK(length(genesis_commitment)=64),
 payload BLOB NOT NULL CHECK(length(payload)>0 AND length(payload)<=262144)
) STRICT;
-- Exclusions deliberately do not depend on an intent FK. Inherited retirement
-- of a legacy/otherwise absent key must remain a blocker, never be discarded.
CREATE TABLE witness_locator_exclusions (
 exclusion_digest TEXT PRIMARY KEY NOT NULL CHECK(length(exclusion_digest)=64),
 account_id TEXT NOT NULL CHECK(length(account_id)=64),
 full_viewing_key_digest TEXT NOT NULL CHECK(length(full_viewing_key_digest)=64),
 payload BLOB NOT NULL CHECK(length(payload)>0 AND length(payload)<=262144)
) STRICT;
CREATE INDEX witness_locator_excluded_accounts ON witness_locator_exclusions(account_id);
CREATE INDEX witness_locator_excluded_fvks ON witness_locator_exclusions(full_viewing_key_digest);

CREATE TRIGGER witness_locator_namespace_no_replace BEFORE INSERT ON witness_locator_namespace
WHEN EXISTS(SELECT 1 FROM witness_locator_namespace)
BEGIN SELECT RAISE(ABORT,'immutable canonical witness namespace'); END;
CREATE TRIGGER witness_locator_namespace_no_update BEFORE UPDATE ON witness_locator_namespace
BEGIN SELECT RAISE(ABORT,'immutable canonical witness namespace'); END;
CREATE TRIGGER witness_locator_namespace_no_delete BEFORE DELETE ON witness_locator_namespace
BEGIN SELECT RAISE(ABORT,'retained canonical witness namespace'); END;
CREATE TRIGGER witness_locator_quarantine_no_replace BEFORE INSERT ON witness_locator_quarantine
WHEN EXISTS(SELECT 1 FROM witness_locator_quarantine)
BEGIN SELECT RAISE(ABORT,'retained locator quarantine'); END;
CREATE TRIGGER witness_locator_quarantine_monotone BEFORE UPDATE ON witness_locator_quarantine
WHEN NEW.singleton!=OLD.singleton OR NEW.quarantined<OLD.quarantined
BEGIN SELECT RAISE(ABORT,'locator quarantine cannot clear'); END;
CREATE TRIGGER witness_locator_quarantine_no_delete BEFORE DELETE ON witness_locator_quarantine
BEGIN SELECT RAISE(ABORT,'retained locator quarantine'); END;

-- BEFORE INSERT collision triggers also defeat INSERT OR REPLACE when SQLite
-- recursive_triggers is disabled. The supported code never uses conflict-ignore.
CREATE TRIGGER witness_locator_intents_no_replace BEFORE INSERT ON witness_locator_intents
WHEN EXISTS(SELECT 1 FROM witness_locator_intents WHERE
 intent_digest=NEW.intent_digest OR account_id=NEW.account_id OR
 full_viewing_key_digest=NEW.full_viewing_key_digest OR
 generation_instance_id=NEW.generation_instance_id OR operation_id=NEW.operation_id OR
 request_digest=NEW.request_digest OR derived_child=NEW.derived_child OR
 local_target_digest=NEW.local_target_digest)
BEGIN SELECT RAISE(ABORT,'immutable account or raw-FVK reservation'); END;
CREATE TRIGGER witness_locator_intents_no_update BEFORE UPDATE ON witness_locator_intents
BEGIN SELECT RAISE(ABORT,'immutable witness creation intent'); END;
CREATE TRIGGER witness_locator_intents_no_delete BEFORE DELETE ON witness_locator_intents
BEGIN SELECT RAISE(ABORT,'uncertain intent remains reserved'); END;
CREATE TRIGGER witness_locator_completions_no_replace BEFORE INSERT ON witness_locator_completions
WHEN EXISTS(SELECT 1 FROM witness_locator_completions WHERE
 intent_digest=NEW.intent_digest OR genesis_commitment=NEW.genesis_commitment)
BEGIN SELECT RAISE(ABORT,'immutable witness completion'); END;
CREATE TRIGGER witness_locator_completions_no_update BEFORE UPDATE ON witness_locator_completions
BEGIN SELECT RAISE(ABORT,'immutable witness completion'); END;
CREATE TRIGGER witness_locator_completions_no_delete BEFORE DELETE ON witness_locator_completions
BEGIN SELECT RAISE(ABORT,'retained witness completion'); END;
CREATE TRIGGER witness_locator_exclusions_no_replace BEFORE INSERT ON witness_locator_exclusions
WHEN EXISTS(SELECT 1 FROM witness_locator_exclusions WHERE exclusion_digest=NEW.exclusion_digest)
BEGIN SELECT RAISE(ABORT,'immutable permanent exclusion'); END;
CREATE TRIGGER witness_locator_exclusions_no_update BEFORE UPDATE ON witness_locator_exclusions
BEGIN SELECT RAISE(ABORT,'immutable permanent exclusion'); END;
CREATE TRIGGER witness_locator_exclusions_no_delete BEFORE DELETE ON witness_locator_exclusions
BEGIN SELECT RAISE(ABORT,'permanent exclusion cannot clear'); END;

CREATE TRIGGER witness_locator_intents_bound BEFORE INSERT ON witness_locator_intents
WHEN (SELECT count(*) FROM witness_locator_intents)>=1024 OR
 length(NEW.payload)+(SELECT coalesce(sum(length(payload)),0) FROM witness_locator_namespace)+
 (SELECT coalesce(sum(length(payload)),0) FROM witness_locator_intents)+
 (SELECT coalesce(sum(length(payload)),0) FROM witness_locator_completions)+
 (SELECT coalesce(sum(length(payload)),0) FROM witness_locator_exclusions)>67108864
BEGIN SELECT RAISE(ABORT,'locator capacity exhausted; no pruning or reset'); END;
CREATE TRIGGER witness_locator_completions_bound BEFORE INSERT ON witness_locator_completions
WHEN (SELECT count(*) FROM witness_locator_completions)>=1024 OR
 length(NEW.payload)+(SELECT coalesce(sum(length(payload)),0) FROM witness_locator_namespace)+
 (SELECT coalesce(sum(length(payload)),0) FROM witness_locator_intents)+
 (SELECT coalesce(sum(length(payload)),0) FROM witness_locator_completions)+
 (SELECT coalesce(sum(length(payload)),0) FROM witness_locator_exclusions)>67108864
BEGIN SELECT RAISE(ABORT,'locator capacity exhausted; no pruning or reset'); END;
CREATE TRIGGER witness_locator_exclusions_bound BEFORE INSERT ON witness_locator_exclusions
WHEN (SELECT count(*) FROM witness_locator_exclusions)>=2048 OR
 length(NEW.payload)+(SELECT coalesce(sum(length(payload)),0) FROM witness_locator_namespace)+
 (SELECT coalesce(sum(length(payload)),0) FROM witness_locator_intents)+
 (SELECT coalesce(sum(length(payload)),0) FROM witness_locator_completions)+
 (SELECT coalesce(sum(length(payload)),0) FROM witness_locator_exclusions)>67108864
BEGIN SELECT RAISE(ABORT,'locator capacity exhausted; no pruning or reset'); END;
