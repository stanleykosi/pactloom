CREATE TABLE store_generation_fences (
 kind TEXT NOT NULL, identity TEXT NOT NULL, detail TEXT NOT NULL,
 PRIMARY KEY(kind,identity)
);
CREATE TABLE store_generation_original_rows (
 table_name TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>=0), payload TEXT NOT NULL,
 PRIMARY KEY(table_name,ordinal)
);
CREATE TRIGGER store_generation_fences_no_update BEFORE UPDATE ON store_generation_fences BEGIN SELECT RAISE(ABORT,'immutable historical fence'); END;
CREATE TRIGGER store_generation_fences_no_delete BEFORE DELETE ON store_generation_fences BEGIN SELECT RAISE(ABORT,'immutable historical fence'); END;
CREATE TRIGGER store_generation_originals_no_update BEFORE UPDATE ON store_generation_original_rows BEGIN SELECT RAISE(ABORT,'immutable historical row'); END;
CREATE TRIGGER store_generation_originals_no_delete BEFORE DELETE ON store_generation_original_rows BEGIN SELECT RAISE(ABORT,'immutable historical row'); END;
CREATE TRIGGER store_generation_records_no_update BEFORE UPDATE ON records WHEN EXISTS(SELECT 1 FROM store_generation_fences WHERE kind='record' AND identity=OLD.aggregate_type||':'||OLD.id) BEGIN SELECT RAISE(ABORT,'historical record requires separate reconciliation'); END;
CREATE TRIGGER store_generation_records_no_delete BEFORE DELETE ON records WHEN EXISTS(SELECT 1 FROM store_generation_fences WHERE kind='record' AND identity=OLD.aggregate_type||':'||OLD.id) BEGIN SELECT RAISE(ABORT,'immutable historical record'); END;
CREATE TRIGGER store_generation_operations_no_update BEFORE UPDATE ON operations WHEN EXISTS(SELECT 1 FROM store_generation_fences WHERE kind='operation' AND identity=OLD.operation_id) BEGIN SELECT RAISE(ABORT,'immutable historical operation'); END;
CREATE TRIGGER store_generation_operations_no_delete BEFORE DELETE ON operations WHEN EXISTS(SELECT 1 FROM store_generation_fences WHERE kind='operation' AND identity=OLD.operation_id) BEGIN SELECT RAISE(ABORT,'immutable historical operation'); END;
CREATE TRIGGER store_generation_effects_no_update BEFORE UPDATE ON effect_intents WHEN EXISTS(SELECT 1 FROM store_generation_fences WHERE kind='effect' AND identity=OLD.operation_id) BEGIN SELECT RAISE(ABORT,'immutable historical effect'); END;
CREATE TRIGGER store_generation_effects_no_delete BEFORE DELETE ON effect_intents WHEN EXISTS(SELECT 1 FROM store_generation_fences WHERE kind='effect' AND identity=OLD.operation_id) BEGIN SELECT RAISE(ABORT,'immutable historical effect'); END;
