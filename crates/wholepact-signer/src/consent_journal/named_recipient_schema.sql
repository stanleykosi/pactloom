-- Additive schema16 retention only. No table creates live signing authority.
-- Profile payload contains private transport material and stays inside SQLCipher.
CREATE TABLE signer_named_recipient_profiles (
 reference TEXT PRIMARY KEY NOT NULL, original_setup_digest TEXT NOT NULL UNIQUE,
 account_id TEXT NOT NULL,
 enrollment_ref TEXT NOT NULL REFERENCES signer_enrollments(reference),
 manifest_ref TEXT NOT NULL REFERENCES signer_accepted_manifests(reference),
 payload TEXT NOT NULL
);
CREATE TABLE signer_named_recipient_originals (
 reference TEXT PRIMARY KEY NOT NULL,
 profile_ref TEXT NOT NULL REFERENCES signer_named_recipient_profiles(reference),
 authorization_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL,
 UNIQUE(authorization_id,reference)
);
CREATE TABLE signer_named_recipient_receipts (
 profile_ref TEXT NOT NULL REFERENCES signer_named_recipient_profiles(reference),
 stream TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>0),
 message_id TEXT NOT NULL, content_hash TEXT NOT NULL,
 payload_digest TEXT NOT NULL, envelope_digest TEXT NOT NULL,
 immutable_slot TEXT, envelope_hex TEXT NOT NULL,
 PRIMARY KEY(profile_ref,stream,sequence),
 UNIQUE(profile_ref,stream,message_id), UNIQUE(profile_ref,immutable_slot)
);
CREATE TABLE signer_named_recipient_started (
 authorization_id TEXT PRIMARY KEY NOT NULL REFERENCES signer_named_recipient_originals(authorization_id),
 original_ref TEXT NOT NULL UNIQUE REFERENCES signer_named_recipient_originals(reference),
 marker_digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL,
 FOREIGN KEY(authorization_id,original_ref) REFERENCES signer_named_recipient_originals(authorization_id,reference)
);
CREATE TABLE signer_named_recipient_results (
 authorization_id TEXT PRIMARY KEY NOT NULL REFERENCES signer_named_recipient_started(authorization_id),
 result_digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL
);
CREATE TRIGGER signer_named_recipient_profiles_no_replace BEFORE INSERT ON signer_named_recipient_profiles WHEN EXISTS(SELECT 1 FROM signer_named_recipient_profiles WHERE reference=NEW.reference OR original_setup_digest=NEW.original_setup_digest) BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_profiles_no_update BEFORE UPDATE ON signer_named_recipient_profiles BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_profiles_no_delete BEFORE DELETE ON signer_named_recipient_profiles BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_originals_no_replace BEFORE INSERT ON signer_named_recipient_originals WHEN EXISTS(SELECT 1 FROM signer_named_recipient_originals WHERE reference=NEW.reference OR authorization_id=NEW.authorization_id) BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_originals_no_update BEFORE UPDATE ON signer_named_recipient_originals BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_originals_no_delete BEFORE DELETE ON signer_named_recipient_originals BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_receipts_no_replace BEFORE INSERT ON signer_named_recipient_receipts WHEN EXISTS(SELECT 1 FROM signer_named_recipient_receipts WHERE profile_ref=NEW.profile_ref AND ((stream=NEW.stream AND (sequence=NEW.sequence OR message_id=NEW.message_id)) OR (immutable_slot IS NOT NULL AND immutable_slot=NEW.immutable_slot))) BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_receipts_no_update BEFORE UPDATE ON signer_named_recipient_receipts BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_receipts_no_delete BEFORE DELETE ON signer_named_recipient_receipts BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_started_no_replace BEFORE INSERT ON signer_named_recipient_started WHEN EXISTS(SELECT 1 FROM signer_named_recipient_started WHERE authorization_id=NEW.authorization_id OR original_ref=NEW.original_ref OR marker_digest=NEW.marker_digest) BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_started_no_update BEFORE UPDATE ON signer_named_recipient_started BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_started_no_delete BEFORE DELETE ON signer_named_recipient_started BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_results_no_replace BEFORE INSERT ON signer_named_recipient_results WHEN EXISTS(SELECT 1 FROM signer_named_recipient_results WHERE authorization_id=NEW.authorization_id OR result_digest=NEW.result_digest) BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_results_no_update BEFORE UPDATE ON signer_named_recipient_results BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;
CREATE TRIGGER signer_named_recipient_results_no_delete BEFORE DELETE ON signer_named_recipient_results BEGIN SELECT RAISE(ABORT,'immutable named recipient history'); END;

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
