CREATE TABLE IF NOT EXISTS receipts (
              stream TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence > 0),
              message_id_digest TEXT NOT NULL, content_digest TEXT NOT NULL,
              slot TEXT, payload_digest TEXT NOT NULL, envelope BLOB NOT NULL,
              PRIMARY KEY(stream, sequence), UNIQUE(stream, message_id_digest));
            CREATE INDEX IF NOT EXISTS receipts_slot ON receipts(slot);
            CREATE TABLE IF NOT EXISTS domain_imports (
              stream TEXT NOT NULL, sequence INTEGER NOT NULL, processor TEXT NOT NULL,
              content_digest TEXT NOT NULL, outcome INTEGER NOT NULL CHECK(outcome IN (1,2)),
              result_digest TEXT NOT NULL, PRIMARY KEY(stream, sequence, processor));