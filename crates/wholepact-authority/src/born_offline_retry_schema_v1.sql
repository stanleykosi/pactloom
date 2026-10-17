CREATE TABLE authority_born_offline_originals (
 operation_id TEXT PRIMARY KEY NOT NULL CHECK(length(operation_id) BETWEEN 1 AND 128),
 request_digest TEXT NOT NULL UNIQUE CHECK(length(request_digest)=64),
 envelope_digest TEXT NOT NULL UNIQUE CHECK(length(envelope_digest)=64),
 export_stream TEXT NOT NULL CHECK(length(export_stream)=64),
 export_sequence INTEGER NOT NULL CHECK(export_sequence>0),
 payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 262144),
 envelope BLOB NOT NULL CHECK(length(envelope) BETWEEN 1 AND 1048576),
 construction_reservation_id TEXT NOT NULL UNIQUE CHECK(length(construction_reservation_id) BETWEEN 1 AND 128),
 UNIQUE(export_stream,export_sequence)
) STRICT;
CREATE TABLE authority_born_offline_receipts (
 operation_id TEXT PRIMARY KEY NOT NULL REFERENCES authority_born_offline_originals(operation_id),
 payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 16384)
) STRICT;
CREATE TRIGGER born_offline_originals_no_replace BEFORE INSERT ON authority_born_offline_originals
WHEN EXISTS(SELECT 1 FROM authority_born_offline_originals WHERE operation_id=NEW.operation_id OR construction_reservation_id=NEW.construction_reservation_id OR request_digest=NEW.request_digest OR envelope_digest=NEW.envelope_digest OR (export_stream=NEW.export_stream AND export_sequence=NEW.export_sequence))
BEGIN SELECT RAISE(ABORT,'immutable born original'); END;
CREATE TRIGGER born_offline_originals_no_update BEFORE UPDATE ON authority_born_offline_originals BEGIN SELECT RAISE(ABORT,'immutable born original'); END;
CREATE TRIGGER born_offline_originals_no_delete BEFORE DELETE ON authority_born_offline_originals BEGIN SELECT RAISE(ABORT,'retained born original'); END;
CREATE TRIGGER born_offline_receipts_no_replace BEFORE INSERT ON authority_born_offline_receipts
WHEN EXISTS(SELECT 1 FROM authority_born_offline_receipts WHERE operation_id=NEW.operation_id)
BEGIN SELECT RAISE(ABORT,'immutable born receipt'); END;
CREATE TRIGGER born_offline_receipts_no_update BEFORE UPDATE ON authority_born_offline_receipts BEGIN SELECT RAISE(ABORT,'immutable born receipt'); END;
CREATE TRIGGER born_offline_receipts_no_delete BEFORE DELETE ON authority_born_offline_receipts BEGIN SELECT RAISE(ABORT,'retained born receipt'); END;
CREATE TRIGGER born_offline_originals_bound BEFORE INSERT ON authority_born_offline_originals
WHEN (SELECT count(*) FROM authority_born_offline_originals)>=1024 OR
 length(NEW.payload)+length(NEW.envelope)+(SELECT coalesce(sum(length(payload)+length(envelope)),0) FROM authority_born_offline_originals)>67108864
BEGIN SELECT RAISE(ABORT,'born original capacity exhausted; no pruning or reset'); END;
