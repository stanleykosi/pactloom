CREATE TABLE IF NOT EXISTS outbox (
                stream TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence > 0),
                message_digest TEXT NOT NULL, preview_digest TEXT NOT NULL, context_digest TEXT NOT NULL,
                sender_fingerprint TEXT NOT NULL, recipient_fingerprint TEXT NOT NULL,
                payload_digest TEXT NOT NULL, slot TEXT, envelope_digest TEXT NOT NULL,
                issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, envelope BLOB NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN (0,1)),
                PRIMARY KEY(stream,sequence), UNIQUE(stream,message_digest));
             CREATE INDEX IF NOT EXISTS outbox_slot ON outbox(slot);