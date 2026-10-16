-- Additive bounded lineage. Prior owner overlays and v1 identity remain intact.
CREATE TABLE store_generation_layers (
 ordinal INTEGER PRIMARY KEY CHECK(ordinal>=1 AND ordinal<16),
 payload TEXT NOT NULL,
 digest TEXT NOT NULL CHECK(length(digest)=64)
);
CREATE TABLE store_generation_layer_rows (
 layer INTEGER NOT NULL REFERENCES store_generation_layers(ordinal),
 table_name TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 payload TEXT NOT NULL,
 PRIMARY KEY(layer,table_name,ordinal)
);
CREATE TABLE store_generation_identities (
 generation_id TEXT PRIMARY KEY CHECK(length(generation_id)=64),
 inventory_digest TEXT NOT NULL CHECK(length(inventory_digest)=64),
 destination_identity TEXT NOT NULL UNIQUE CHECK(length(destination_identity)=64)
);
CREATE TRIGGER store_generation_layers_no_update BEFORE UPDATE ON store_generation_layers BEGIN SELECT RAISE(ABORT,'immutable generation lineage'); END;
CREATE TRIGGER store_generation_layers_no_delete BEFORE DELETE ON store_generation_layers BEGIN SELECT RAISE(ABORT,'immutable generation lineage'); END;
CREATE TRIGGER store_generation_layer_rows_no_update BEFORE UPDATE ON store_generation_layer_rows BEGIN SELECT RAISE(ABORT,'immutable generation row'); END;
CREATE TRIGGER store_generation_layer_rows_no_delete BEFORE DELETE ON store_generation_layer_rows BEGIN SELECT RAISE(ABORT,'immutable generation row'); END;
CREATE TRIGGER store_generation_identities_no_update BEFORE UPDATE ON store_generation_identities BEGIN SELECT RAISE(ABORT,'immutable generation identity'); END;
CREATE TRIGGER store_generation_identities_no_delete BEFORE DELETE ON store_generation_identities BEGIN SELECT RAISE(ABORT,'immutable generation identity'); END;
