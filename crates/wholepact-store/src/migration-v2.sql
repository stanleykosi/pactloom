CREATE TABLE store_recovery (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 recovery_required INTEGER NOT NULL CHECK(recovery_required IN(0,1)),
 restored_at_ms INTEGER,
 source_snapshot_digest TEXT,
 CHECK((recovery_required=0 AND restored_at_ms IS NULL AND source_snapshot_digest IS NULL)
    OR (recovery_required=1 AND restored_at_ms IS NOT NULL AND length(source_snapshot_digest)=64))
);
INSERT INTO store_recovery(singleton,recovery_required) VALUES(1,0);
