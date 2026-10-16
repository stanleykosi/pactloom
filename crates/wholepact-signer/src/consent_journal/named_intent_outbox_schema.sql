-- Additive proposal for the still-unpublished signer schema16. It is not yet
-- registered or qualified. The exact original payload retains request/template.
CREATE TABLE signer_named_intent_outbox (
 authorization_id TEXT PRIMARY KEY NOT NULL REFERENCES signer_named_recipient_originals(authorization_id),
 original_ref TEXT NOT NULL UNIQUE REFERENCES signer_named_recipient_originals(reference),
 profile_ref TEXT NOT NULL REFERENCES signer_named_recipient_profiles(reference),
 stream TEXT NOT NULL,
 sequence INTEGER NOT NULL CHECK(sequence>0),
 message_id TEXT NOT NULL,
 content_hash TEXT NOT NULL,
 payload_digest TEXT NOT NULL,
 envelope_digest TEXT NOT NULL,
 preview_json TEXT NOT NULL,
 envelope_hex TEXT NOT NULL,
 UNIQUE(profile_ref,stream,sequence),
 UNIQUE(profile_ref,stream,message_id),
 FOREIGN KEY(authorization_id,original_ref) REFERENCES signer_named_recipient_originals(authorization_id,reference)
);
CREATE TRIGGER signer_named_intent_outbox_no_update BEFORE UPDATE ON signer_named_intent_outbox BEGIN SELECT RAISE(ABORT,'immutable named intent outbox'); END;
CREATE TRIGGER signer_named_intent_outbox_no_delete BEFORE DELETE ON signer_named_intent_outbox BEGIN SELECT RAISE(ABORT,'immutable named intent outbox'); END;
CREATE TRIGGER signer_named_intent_outbox_no_replace BEFORE INSERT ON signer_named_intent_outbox WHEN EXISTS(
 SELECT 1 FROM signer_named_intent_outbox WHERE authorization_id=NEW.authorization_id OR original_ref=NEW.original_ref OR (profile_ref=NEW.profile_ref AND stream=NEW.stream AND (sequence=NEW.sequence OR message_id=NEW.message_id))
) BEGIN SELECT RAISE(ABORT,'immutable named intent outbox'); END;
