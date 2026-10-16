CREATE TABLE authority_offline_outcomes (
 prepared_digest TEXT PRIMARY KEY REFERENCES authority_offline_original_receipts(prepared_digest),
 outcome_kind TEXT NOT NULL CHECK(outcome_kind IN('admission','no_admission','exposure_retained')),
 decision_digest TEXT NOT NULL UNIQUE CHECK(length(decision_digest)=64),
 emission_may_have_started INTEGER NOT NULL CHECK(emission_may_have_started=1),
 payload BLOB NOT NULL CHECK(length(payload)>0 AND length(payload)<=262144)
);
CREATE TRIGGER offline_outcome_no_update BEFORE UPDATE ON authority_offline_outcomes BEGIN SELECT RAISE(ABORT,'single immutable offline outcome'); END;
CREATE TRIGGER offline_outcome_no_delete BEFORE DELETE ON authority_offline_outcomes BEGIN SELECT RAISE(ABORT,'emission uncertainty cannot be erased'); END;
