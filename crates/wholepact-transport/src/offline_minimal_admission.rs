//! Narrow witness-authenticated projection. Source-only, unqualified staging.
//! The legacy raw descriptor/kind is deliberately neither accepted nor rewritten.
// Canonical production source is also compiled inside the private witness owner.
include!("offline_minimal_admission_core.rs");

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovered_minimal_history_never_claims_delivery_or_authorization() {
        let history = RecoveredOfflineMinimalAdmission {
            statement: statement_fixture(),
            envelope_digest: "a".repeat(64),
            content_digest: "b".repeat(64),
            original_order: MessageOrder {
                message_id: "c".repeat(32),
                sequence: 1,
                issued_at: Timestamp::from_unix_seconds(100).unwrap(),
                expires_at: Timestamp::from_unix_seconds(200).unwrap(),
            },
        };
        assert!(!history.authorization_allowed());
        assert!(!history.is_new_delivery());
        assert_eq!(history.original_order().expires_at.unix_seconds(), 200);
        assert!(history.statement() == &statement_fixture());
    }
    #[test]
    fn new_kind_requires_qualified_export_and_cannot_alias_raw_descriptor() {
        assert!(ArtifactKind::OfflineMinimalAuthorityAdmission.requires_qualified_export());
        assert_ne!(
            ArtifactKind::OfflineMinimalAuthorityAdmission,
            ArtifactKind::OfflineAuthorityAdmission
        );
        assert_ne!(
            OFFLINE_MINIMAL_ADMISSION_FIELD,
            crate::OFFLINE_ADMISSION_FIELD
        );
    }
    #[test]
    fn legacy_sensitive_fields_are_not_accepted_by_minimal_statement() {
        for key in [
            "account_outstanding_debit_zatoshis",
            "account_reserved_input_value_zatoshis",
            "writer_session_id",
            "request",
            "writer_epoch",
            "policy",
            "unrelated_history",
        ] {
            let mut value = serde_json::to_value(statement_fixture()).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert(key.into(), serde_json::json!("private-canary"));
            assert!(
                crate::types::parse::<OfflineMinimalAdmission>(
                    &serde_json::to_vec(&value).unwrap()
                )
                .is_err()
            );
        }
    }
    fn statement_fixture() -> OfflineMinimalAdmission {
        let h = "a".repeat(64);
        OfflineMinimalAdmission {
            schema_version: 1,
            witness_id: "synthetic-witness".into(),
            witness_transport_key_digest: h.clone(),
            witness_policy_digest: h.clone(),
            operation_id: "synthetic-operation".into(),
            authorization_id: "synthetic-authorization".into(),
            request_digest: h.clone(),
            intent_digest: h.clone(),
            terms_digest: h.clone(),
            review_package_digest: h.clone(),
            original_admission_digest: h.clone(),
            original_export_plan_digest: h.clone(),
            committed_head: AuthorityHead {
                sequence: 1,
                digest: h,
            },
            reserved_at_ms: 1000,
            admission_expires_at_ms: 2000,
        }
    }
    #[test]
    fn minimal_statement_binds_all_digest_time_and_head_fields() {
        let original = statement_fixture();
        original.validate().unwrap();
        let original_digest = original.statement_digest().unwrap();
        for changed in [
            "intent",
            "terms",
            "package",
            "request",
            "admission",
            "plan",
            "head",
        ] {
            let mut s = original.clone();
            let field = match changed {
                "intent" => &mut s.intent_digest,
                "terms" => &mut s.terms_digest,
                "package" => &mut s.review_package_digest,
                "request" => &mut s.request_digest,
                "admission" => &mut s.original_admission_digest,
                "plan" => &mut s.original_export_plan_digest,
                _ => &mut s.committed_head.digest,
            };
            *field = "b".repeat(64);
            assert_ne!(s.statement_digest().unwrap(), original_digest);
        }
        let mut expired = original.clone();
        expired.reserved_at_ms = expired.admission_expires_at_ms;
        assert!(expired.validate().is_err());
        let mut version = original;
        version.schema_version = 2;
        assert_eq!(version.validate(), Err(TransportError::UnsupportedVersion));
    }
    #[test]
    fn raw_and_minimal_share_original_durable_stream_and_sequence_fence() {
        let mut old = MessageContext {
            network_profile_id: "synthetic-network".into(),
            agreement_id: "synthetic-agreement".into(),
            proposal_id: "synthetic-proposal".into(),
            proposal_revision: 1,
            sender_id: "offline-admission:synthetic-policy".into(),
            recipient_id: "offline-admission:synthetic-signer".into(),
            artifact_kind: ArtifactKind::OfflineAuthorityAdmission,
        };
        let original_stream = crate::replay::stream_digest(&old).unwrap();
        old.artifact_kind = ArtifactKind::OfflineMinimalAuthorityAdmission;
        assert_eq!(crate::replay::stream_digest(&old).unwrap(), original_stream);
        for first in [
            ArtifactKind::OfflineAuthorityAdmission,
            ArtifactKind::OfflineMinimalAuthorityAdmission,
            ArtifactKind::OfflineAdmissionControl,
        ] {
            for second in [
                ArtifactKind::OfflineAuthorityAdmission,
                ArtifactKind::OfflineMinimalAuthorityAdmission,
                ArtifactKind::OfflineAdmissionControl,
            ] {
                if first == second {
                    continue;
                }
                old.artifact_kind = first;
                let first_stream = crate::replay::stream_digest(&old).unwrap();
                old.artifact_kind = second;
                assert_eq!(crate::replay::stream_digest(&old).unwrap(), first_stream);
                assert_same_plan_excludes_other_representation(&first_stream, first, second);
            }
        }
    }
    fn assert_same_plan_excludes_other_representation(
        original_stream: &str,
        first: ArtifactKind,
        second: ArtifactKind,
    ) {
        // Actual outbox schema, no credentials, HPKE, files or proof execution.
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(crate::outbox::OUTBOX_SCHEMA).unwrap();
        let insert = "INSERT INTO outbox(stream,sequence,message_digest,preview_digest,context_digest,sender_fingerprint,recipient_fingerprint,payload_digest,slot,envelope_digest,issued_at,expires_at,envelope) VALUES(?1,1,'same-message',?2,?3,'sender','recipient','payload',NULL,'envelope',1,2,x'00')";
        let first_preview = format!("first:{first:?}");
        let second_preview = format!("second:{second:?}");
        c.execute(
            insert,
            rusqlite::params![original_stream, first_preview, "first-context"],
        )
        .unwrap();
        // The real enqueue SELECT finds this row before it reaches sealing.
        let prior: String = c.query_row("SELECT preview_digest FROM outbox WHERE stream=?1 AND (sequence=?2 OR message_digest=?3)",
            rusqlite::params![original_stream, 1, "same-message"], |r| r.get(0)).unwrap();
        assert_ne!(prior, second_preview);
        assert!(
            c.execute(
                insert,
                rusqlite::params![original_stream, second_preview, "second-context"]
            )
            .is_err()
        );
    }
}
