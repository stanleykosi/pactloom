// Canonical production source is also compiled inside the private witness owner.
include!("envelope_core.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteReplayLedger;

    // Deliberately bypasses the export consent checks only inside this synthetic
    // adversarial fixture, to verify independent receiver-side digest validation.
    fn malicious_authenticated_file(
        wire: &ProtectedMessage,
        sender: &TransportSecret,
        recipient: &TransportPublicKey,
        pretty: bool,
    ) -> EncryptedEnvelope {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let mut rng = rand::rngs::StdRng::from_seed(seed);
        let secret = sender.private_key().unwrap();
        let (encapped, mut context) =
            hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, Kem>(
                &OpModeS::Auth((secret.clone(), Kem::sk_to_pk(&secret))),
                &recipient.key().unwrap(),
                INFO,
                &mut rng,
            )
            .unwrap();
        let mut envelope = WireEnvelope {
            schema_version: 1,
            suite: SUITE.into(),
            encapsulated_key: hex::encode(encapped.to_bytes()),
            ciphertext: String::new(),
        };
        let bytes = if pretty {
            serde_json::to_vec_pretty(wire).unwrap()
        } else {
            encode(wire).unwrap()
        };
        envelope.ciphertext = b64(&context
            .seal(&Zeroizing::new(bytes), &envelope.aad().unwrap())
            .unwrap());
        EncryptedEnvelope(encode(&envelope).unwrap())
    }
    #[test]
    fn authenticated_sender_cannot_skip_receiver_payload_and_preview_consistency() {
        let sender = TransportSecret::from_bytes([71; 32]).unwrap();
        let recipient = TransportSecret::from_bytes([72; 32]).unwrap();
        let now = Timestamp::from_unix_seconds(1_000).unwrap();
        let expected = MessageContext {
            network_profile_id: "testnet-synthetic".into(),
            agreement_id: "agreement".into(),
            proposal_id: "proposal".into(),
            proposal_revision: 1,
            sender_id: "sender".into(),
            recipient_id: "recipient".into(),
            artifact_kind: ArtifactKind::Contribution,
        };
        let dir = std::env::temp_dir().join(format!(
            "wholepact-synthetic-authenticated-mutation-{}",
            random_message_id().unwrap()
        ));
        std::fs::create_dir(&dir).unwrap();
        let mut ledger = SqliteReplayLedger::open(dir.join("ledger.sqlite")).unwrap();
        for variant in 0..6 {
            let prepared = prepare_export(
                ExportRequest {
                    context: expected.clone(),
                    order: MessageOrder {
                        message_id: "00000000000000000000000000000001".into(),
                        sequence: 1,
                        issued_at: now.clone(),
                        expires_at: Timestamp::from_unix_seconds(1_100).unwrap(),
                    },
                    purpose: "synthetic adversarial fixture".into(),
                    persistence_warning: "recipient retains bytes".into(),
                },
                vec![DisclosureField::new("field", b"selected-only".to_vec()).unwrap()],
                &sender.public_key().unwrap(),
                &recipient.public_key().unwrap(),
                &now,
            )
            .unwrap();
            let mut wire = ProtectedMessage {
                approved_preview_digest: prepared.preview.digest().unwrap(),
                preview: prepared.preview,
                fields: encode_fields(&prepared.fields),
            };
            match variant {
                0 => wire.fields[0].data = b64(b"unreviewed additional private data"),
                1 => wire.preview.payload_digest = "00".repeat(32),
                2 => wire.preview.fields[0].sha256 = "00".repeat(32),
                3 => wire.approved_preview_digest = "00".repeat(32),
                _ => {}
            }
            let file = malicious_authenticated_file(
                &wire,
                &sender,
                &recipient.public_key().unwrap(),
                variant == 5,
            );
            let result = open_envelope(
                &file,
                &recipient,
                &sender.public_key().unwrap(),
                &expected,
                &now,
                &mut ledger,
            );
            match variant {
                0..=3 => assert_eq!(result.err(), Some(TransportError::DisclosureDenied)),
                4 => assert!(result.is_ok()),
                _ => assert_eq!(result.err(), Some(TransportError::Replay)),
            }
            assert_eq!(
                ledger.record_count().unwrap(),
                if variant < 4 { 0 } else { 1 }
            );
        }
        drop(ledger);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod control_route_tests {
    use super::*;
    struct NeverLedger;
    impl ReplayLedger for NeverLedger {
        fn accept_authenticated(&mut self, _: &AuthenticatedReceipt, _: &[u8]) -> Result<()> {
            panic!("generic control must fail before ledger access")
        }
    }
    #[test]
    fn generic_control_rejects_before_authentication_callback_or_ledger() {
        // Deliberately malformed bytes and synthetic non-live key objects. No
        // HPKE roundtrip is needed to establish the public preledger guard.
        let envelope = EncryptedEnvelope(Vec::new());
        let recipient = TransportSecret::from_bytes([7; 32]).unwrap();
        let sender = TransportPublicKey::from_bytes([8; 32]).unwrap();
        let expected = MessageContext {
            network_profile_id: "synthetic".into(),
            agreement_id: "agreement".into(),
            proposal_id: "proposal".into(),
            proposal_revision: 1,
            sender_id: "witness".into(),
            recipient_id: "signer".into(),
            artifact_kind: ArtifactKind::OfflineAdmissionControl,
        };
        let now = Timestamp::from_unix_seconds(1).unwrap();
        assert_eq!(
            open_envelope(
                &envelope,
                &recipient,
                &sender,
                &expected,
                &now,
                &mut NeverLedger
            )
            .err(),
            Some(TransportError::AuthorityUnavailable)
        );
        assert_eq!(
            open_envelope_checked(
                &envelope,
                &recipient,
                &sender,
                &expected,
                &now,
                &mut NeverLedger,
                |_| panic!("generic control must fail before callback")
            )
            .err(),
            Some(TransportError::AuthorityUnavailable)
        );
        // The crate-private authenticator used by the concrete atomic importer
        // is not disabled by this generic guard: it reaches payload validation.
        // A successful complete atomic import still requires HPKE qualification.
        assert_eq!(
            authenticate(&envelope, &recipient, &sender, &expected, Some(&now)).err(),
            Some(TransportError::Malformed)
        );
    }
}

#[cfg(test)]
mod offline_raw_seal_tests {
    use super::*;
    #[test]
    fn raw_offline_seal_refuses_before_time_consent_key_or_hpke_processing() {
        let public = TransportPublicKey::from_bytes([0x61; 32]).unwrap();
        let secret = TransportSecret::from_bytes([0x62; 32]).unwrap();
        for kind in [
            ArtifactKind::OfflineReservationIntent,
            ArtifactKind::OfflineAuthorityAdmission,
            ArtifactKind::OfflineAdmissionControl,
            ArtifactKind::Authorization,
        ] {
            let prepared = prepare_export(
                ExportRequest {
                    context: MessageContext {
                        network_profile_id: "synthetic".into(),
                        agreement_id: "agreement".into(),
                        proposal_id: "proposal".into(),
                        proposal_revision: 1,
                        sender_id: "sender".into(),
                        recipient_id: "recipient".into(),
                        artifact_kind: kind,
                    },
                    order: MessageOrder {
                        message_id: "11".repeat(16),
                        sequence: 1,
                        issued_at: Timestamp::from_unix_seconds(1).unwrap(),
                        expires_at: Timestamp::from_unix_seconds(2).unwrap(),
                    },
                    purpose: "Synthetic guard test".into(),
                    persistence_warning: "Synthetic retained evidence".into(),
                },
                vec![DisclosureField::new("synthetic", b"{}".to_vec()).unwrap()],
                &public,
                &public,
                &Timestamp::from_unix_seconds(1).unwrap(),
            )
            .unwrap();
            // Wrong key, missing approval and expired time must not reach HPKE.
            let error = prepared
                .seal(
                    &secret,
                    "not-approved",
                    &Timestamp::from_unix_seconds(3).unwrap(),
                )
                .err();
            assert_eq!(
                error,
                Some(if kind == ArtifactKind::Authorization {
                    TransportError::InvalidTime // Existing unrelated semantics remain unchanged.
                } else {
                    TransportError::AuthorityUnavailable
                })
            );
        }
    }
}

#[cfg(test)]
mod minimal_admission_generic_guards {
    use super::*;
    #[test]
    fn minimal_kind_has_no_generic_seal_enqueue_or_open_route_in_any_feature_profile() {
        let kind = ArtifactKind::OfflineMinimalAuthorityAdmission;
        assert!(kind.requires_qualified_export());
        assert_eq!(
            reject_unqualified_offline_seal(kind),
            Err(TransportError::AuthorityUnavailable)
        );
        let expected = MessageContext {
            network_profile_id: "synthetic".into(),
            agreement_id: "synthetic".into(),
            proposal_id: "synthetic".into(),
            proposal_revision: 1,
            sender_id: "synthetic".into(),
            recipient_id: "synthetic".into(),
            artifact_kind: kind,
        };
        assert_eq!(
            reject_generic_control(&expected),
            Err(TransportError::AuthorityUnavailable)
        );
    }
}

#[cfg(test)]
mod offline_return_generic_guard_tests {
    use super::*;
    #[test]
    fn offline_return_cannot_use_generic_seal_or_open() {
        let kind = ArtifactKind::OfflineAuthorizationReturn;
        let context = MessageContext {
            network_profile_id: "ironwood-testnet-nu7-candidate".into(),
            agreement_id: "synthetic-agreement".into(),
            proposal_id: "synthetic-proposal".into(),
            proposal_revision: 1,
            sender_id: "offline-return:synthetic-sender".into(),
            recipient_id: "offline-return:synthetic-recipient".into(),
            artifact_kind: kind,
        };
        assert_eq!(
            reject_unqualified_offline_seal(kind),
            Err(TransportError::AuthorityUnavailable)
        );
        assert_eq!(
            reject_generic_control(&context),
            Err(TransportError::AuthorityUnavailable)
        );
        assert!(kind.immutable_slot());
        assert!(kind.requires_qualified_export());
        assert_ne!(
            serde_json::to_string(&kind).unwrap(),
            serde_json::to_string(&ArtifactKind::Authorization).unwrap()
        );
    }
}

#[cfg(test)]
#[path = "retained_metadata_tests.rs"]
mod retained_metadata_tests;
