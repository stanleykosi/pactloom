CREATE TABLE records (
 aggregate_type TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>=0),
 payload TEXT NOT NULL, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL,
 PRIMARY KEY(aggregate_type,id)
);
CREATE TABLE operations (
 operation_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, kind TEXT NOT NULL, resource_id TEXT NOT NULL,
 status TEXT NOT NULL, result TEXT NOT NULL, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);
CREATE TABLE idempotency (
 principal_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_digest TEXT NOT NULL, result TEXT NOT NULL,
 PRIMARY KEY(principal_id,idempotency_key)
);
CREATE TABLE events (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, aggregate_type TEXT NOT NULL, aggregate_id TEXT NOT NULL,
 aggregate_revision INTEGER NOT NULL CHECK(aggregate_revision>=0), kind TEXT NOT NULL, payload TEXT NOT NULL,
 operation_id TEXT NOT NULL, occurred_at_ms INTEGER NOT NULL
);
CREATE TABLE authority_accounts (
 account_id TEXT PRIMARY KEY, writer_epoch INTEGER NOT NULL CHECK(writer_epoch>=0), recovery_required INTEGER NOT NULL CHECK(recovery_required IN(0,1))
);
CREATE TABLE authority_exposures (
 authorization_id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES authority_accounts(account_id),
 obligation_id TEXT NOT NULL, proposal_id TEXT NOT NULL, request_digest TEXT NOT NULL,
 maximum_debit TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN('authorized_locally','released','outstanding_uncertain','expired_observed','conflicted_observed','consumed')), release_intent INTEGER NOT NULL CHECK(release_intent IN(0,1)),
 payload TEXT NOT NULL, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);
CREATE TABLE authority_reservations (
 account_id TEXT NOT NULL REFERENCES authority_accounts(account_id), input_id TEXT NOT NULL,
 authorization_id TEXT NOT NULL REFERENCES authority_exposures(authorization_id),
 PRIMARY KEY(account_id,input_id)
);
CREATE TABLE authority_events (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT, authorization_id TEXT NOT NULL, kind TEXT NOT NULL,
 evidence_ref TEXT, occurred_at_ms INTEGER NOT NULL
);
CREATE TABLE effect_intents (
 operation_id TEXT PRIMARY KEY, kind TEXT NOT NULL, resource_id TEXT NOT NULL, payload_digest TEXT NOT NULL,
 protected_payload_ref TEXT NOT NULL, status TEXT NOT NULL, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);
