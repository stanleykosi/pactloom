//! Synthetic-only local assembly from actual consumed owner and independently
//! authenticated artifacts. Output is an UNAPPROVED draft for the unchanged
//! genuine native first-original pipeline; no rows or signatures are created.
use super::*;
use crate::account::birth::enrollment::roster_v2::inventory::common_context_reentry_v1::named_recipient::ConsumedBornNamedSourceV1;
use crate::native_ui::PendingAccountNativeAuthority;
use super::super::{named_intent_transport as wire, named_recipient_records::*};
use wholepact_authority::{AuthorityClient, OwnerControl, OfflineAdmissionExportPlan,
    born_offline_checkpoint_origin_v1::{BornOfflineCheckpointOriginV1,BornOfflineCheckpointExportPlanV1},
    born_offline_construction_v1::BornOfflineConstructionLinkV1,
    born_offline_admission_v1::BornOfflineReservationRequestV1,
    offline::{OfflineAuthorizationTerms,OfflineReservationIntent,ReserveOfflineAuthorization}};
use wholepact_protocol::own_effects::{OwnEffectsPolicy,OwnOutputPurpose};
use wholepact_signer_origin::named_verifier_policy::NamedVerifierPolicyScopeV1;
use wholepact_offline_bridge::{NamedVerifierPackageV1,NamedVerifierExpectedContext,
    inspect_named_verifier_package,named_verifier_original_context_digest};
use wholepact_transport::{EncryptedEnvelope,NamedReviewBindingV1,NAMED_REVIEW_DISCLOSURE_PROFILE_V1,
    MessageOrder,Timestamp,MAX_FILE_BYTES};

/// Inert untrusted artifacts, which may contain private payment metadata.
/// This does not contain private own viewing
/// data, a signer origin, native consent, an admission or current chain authority.
pub struct OriginalNamedPaymentArtifactsV1 {
    pub terms: OfflineAuthorizationTerms,
    pub verifier_scope: NamedVerifierPolicyScopeV1,
    pub expected_transformation_digest: String,
    pub own_context: Vec<u8>,
    pub checkpoint_origin: BornOfflineCheckpointOriginV1,
    pub checkpoint_plan: BornOfflineCheckpointExportPlanV1,
    pub checkpoint_ciphertext: Vec<u8>,
    pub assertion_ciphertext: Vec<u8>,
}
fn invalid(_: impl std::fmt::Display) -> crate::Error {
    crate::Error::Verification
}
fn message_id(domain: &str, original: &str) -> String {
    hex::encode(Sha256::digest(format!("{domain}\0{original}").as_bytes()))[..32].into()
}
impl LiveNamedRecipientProfile {
    pub(crate) fn synthetic_assemble_born_original(
        &self,
        actual: &ConsumedBornNamedSourceV1,
        native: &PendingAccountNativeAuthority,
        session: &SignerConsentSession,
        client: &AuthorityClient,
        own_policy: OwnEffectsPolicy,
        input: OriginalNamedPaymentArtifactsV1,
    ) -> crate::Result<BornNamedRecipientOriginalInputs> {
        actual.check(native)?;
        self.check_current(actual.journal(), session)?;
        let op = NamedRecipientOperation::new();
        let h = client
            .reconcile_history_checked_until(
                op.deadline()
                    .min(native.native().binding().bounded_deadline()?),
                || {
                    actual
                        .check(native)
                        .map_err(|_| wholepact_authority::AuthorityError::Permission)?;
                    op.check()
                        .map_err(|_| wholepact_authority::AuthorityError::Permission)
                },
            )
            .map_err(invalid)?;
        let p = &self.record;
        let c = actual.construction();
        let e = h
            .born_offline_enrollment_v1()
            .map_err(invalid)?
            .ok_or(crate::Error::Unavailable)?;
        let artifacts = h
            .born_offline_artifacts_v1()
            .map_err(invalid)?
            .ok_or(crate::Error::Unavailable)?;
        let scope = &input.verifier_scope;
        let proposal = scope.validate().map_err(invalid)?;
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(invalid)?
            .as_millis()
            .try_into()
            .map_err(invalid)?;
        if input.checkpoint_ciphertext.len() > MAX_FILE_BYTES
            || input.assertion_ciphertext.len() > MAX_FILE_BYTES
            || input.own_context.len() > 1024 * 1024
            || input.own_context.is_empty()
            || scope.account_id != p.account_id
            || scope.enrollment_ref != p.enrollment_ref
            || scope.accepted_manifest_ref != p.manifest_ref
            || scope.verifier_public_key != p.verifier_signing_public_key
            || scope.proposal
                != *c
                    .reservation
                    .request
                    .construction
                    .plan
                    .validate()
                    .map_err(invalid)?
                    .input()
            || proposal.manifest_digest() != input.terms.manifest_digest
            || scope.original_artifact_digest != input.checkpoint_origin.proved_artifact_digest
            || h.account_use_history().genesis() != Some(actual.genesis())
            || now_ms < scope.original_validity_not_before_ms
            || now_ms >= scope.original_validity_expires_ms
        {
            return Err(crate::Error::ReviewMismatch);
        }
        // Required original provenance, never a fabricated new observation.
        input
            .checkpoint_origin
            .require_historical_provenance_v2()
            .map_err(invalid)?;
        input
            .checkpoint_origin
            .validate_snapshot_terms(&input.terms)
            .map_err(invalid)?;
        input
            .checkpoint_origin
            .validate_for_origin(c)
            .map_err(invalid)?;
        let (original_read, original_admission) = actual.original_common_context_read(native)?;
        input
            .checkpoint_origin
            .validate_historical_read(
                &c.reservation.request.construction.plan,
                original_read,
                original_admission,
            )
            .map_err(invalid)?;
        artifacts
            .binding
            .validate_enrollment(&e.enrollment)
            .map_err(invalid)?;
        let expected =
            born_checkpoint_projection(p, &input.checkpoint_origin, &input.checkpoint_plan)
                .map_err(invalid)?;
        let checkpoint =
            wire::EncryptedEnvelope::from_bytes(input.checkpoint_ciphertext).map_err(invalid)?;
        let recipient = wire::TransportSecret::from_bytes(p.transport_secret).map_err(invalid)?;
        let sender =
            wire::TransportPublicKey::from_bytes(p.return_transport_public_key).map_err(invalid)?;
        let context: wire::MessageContext = serde_json::from_value(
            serde_json::to_value(&expected.preview().context).map_err(invalid)?,
        )
        .map_err(invalid)?;
        let (received, receipt) =
            wire::authenticate(&checkpoint, &recipient, &sender, &context, None)
                .map_err(invalid)?;
        if serde_json::to_vec(received.preview()).map_err(invalid)?
            != serde_json::to_vec(expected.preview()).map_err(invalid)?
            || received.fields().len() != expected.fields().len()
            || received
                .fields()
                .iter()
                .zip(expected.fields())
                .any(|(a, b)| a.name() != b.name() || a.bytes() != b.bytes())
        {
            return Err(crate::Error::ReviewMismatch);
        }
        let checkpoint_receipt = BornNamedCheckpointReceiptV1 {
            version: 1,
            profile_ref: p.reference.clone(),
            checkpoint_origin_digest: input.checkpoint_origin.digest().map_err(invalid)?,
            export_plan: input.checkpoint_plan,
            stream_digest: receipt.stream_digest().into(),
            sequence: receipt.sequence(),
            message_id_digest: receipt.message_id_digest().into(),
            content_digest: receipt.content_digest().into(),
            payload_digest: receipt.payload_digest().into(),
            envelope_digest: receipt.envelope_digest().into(),
            immutable_slot_digest: receipt
                .immutable_slot_digest()
                .ok_or(crate::Error::ReviewMismatch)?
                .into(),
        };
        checkpoint_receipt
            .validate_for(p, &input.checkpoint_origin)
            .map_err(invalid)?;
        let assertion =
            wire::EncryptedEnvelope::from_bytes(input.assertion_ciphertext).map_err(invalid)?;
        let context = wire::MessageContext {
            network_profile_id: input.terms.network_profile_id.clone(),
            agreement_id: input.terms.agreement_id.clone(),
            proposal_id: input.terms.proposal_id.clone(),
            proposal_revision: input.terms.proposal_revision,
            sender_id: hex::encode(Sha256::digest(p.verifier_signing_public_key)),
            recipient_id: p.account_id.clone(),
            artifact_kind: wire::ArtifactKind::NamedVerifierAssertion,
        };
        let sender = wire::TransportPublicKey::from_bytes(p.verifier_transport_public_key)
            .map_err(invalid)?;
        let (received, _) =
            wire::authenticate(&assertion, &recipient, &sender, &context, None).map_err(invalid)?;
        if received.fields().len() != 1
            || received.fields()[0].name() != "named-verifier-assertion-v1"
        {
            return Err(crate::Error::ReviewMismatch);
        }
        let bytes = received.fields()[0].bytes();
        let package = NamedVerifierPackageV1::parse(bytes).map_err(invalid)?;
        let original_context =
            named_verifier_original_context_digest(&input.terms).map_err(invalid)?;
        let inspection = inspect_named_verifier_package(
            bytes,
            &own_policy,
            &p.verifier_signing_public_key,
            &NamedVerifierExpectedContext {
                original_artifact_digest: &input.checkpoint_origin.proved_artifact_digest,
                transformation_commitment: &input.expected_transformation_digest,
                manifest_digest: &input.terms.manifest_digest,
                original_context_digest: &original_context,
                original_request_digest: &scope.original_request_digest,
                validity_not_before_ms: scope.original_validity_not_before_ms,
                validity_expires_ms: scope.original_validity_expires_ms,
                transaction_expiry_height: input.terms.transaction_expiry_height,
                own_account_id: &p.account_id,
            },
        )
        .map_err(invalid)?;
        let package_digest = inspection.package_digest().to_owned();
        let mut terms = input.terms;
        terms.review_package_digest = NamedReviewBindingV1 {
            schema_version: 1,
            disclosure_profile: NAMED_REVIEW_DISCLOSURE_PROFILE_V1.into(),
            owner_setup_digest: p.original_setup_digest.clone(),
            assertion_package_digest: package_digest.clone(),
            original_context_digest: original_context.clone(),
        }
        .review_package_digest()
        .map_err(invalid)?;
        if named_verifier_original_context_digest(&terms).map_err(invalid)? != original_context {
            return Err(crate::Error::ReviewMismatch);
        }
        // Align the NEW local request to a real whole-second boundary because
        // maintained admission export times must be >= request and <= commit.
        // This is not observation provenance and renews no original deadline.
        let request_start = now_ms
            .div_ceil(1000)
            .checked_mul(1000)
            .ok_or(crate::Error::InvalidData)?;
        loop {
            native.check_current()?;
            op.check().map_err(invalid)?;
            let wall: u64 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(invalid)?
                .as_millis()
                .try_into()
                .map_err(invalid)?;
            if wall >= request_start {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let expires = scope
            .original_validity_expires_ms
            .min(e.enrollment.policy.expires_at_ms)
            .min(e.enrollment.original_writer_session.expires_at_ms)
            .min(c.reservation.construction_expires_at_ms)
            .min(
                request_start
                    .checked_add(e.enrollment.policy.maximum_admission_lifetime_ms)
                    .ok_or(crate::Error::InvalidData)?,
            );
        let issued_second = request_start / 1000;
        let last_second = expires / 1000;
        if issued_second >= last_second {
            return Err(crate::Error::Locked);
        }
        // Native review/reference/request commitments are intentionally absent.
        // The maintained importer normalizes them under its real local owner
        // before validating the full draft, and never accepts them as consent.
        let reservation = ReserveOfflineAuthorization {
            schema_version: 1,
            operation_id: format!("born-reserve-{}", terms.authorization_id),
            writer_epoch: e.enrollment.original_writer_session.writer_epoch,
            expected_head: h.snapshot().head.clone(),
            intent: OfflineReservationIntent {
                schema_version: 1,
                intent_id: format!("born-intent-{}", terms.authorization_id),
                terms: terms.clone(),
                native_reservation_review_digest: String::new(),
            },
            requested_at_ms: request_start,
            admission_expires_at_ms: expires,
        };
        let link = BornOfflineConstructionLinkV1 {
            version: 1,
            reservation_operation_id: c.reservation.request.construction.operation_id.clone(),
            reservation_digest: c
                .reservation
                .digest_for(&c.extension, &c.continuation)
                .map_err(invalid)?,
            consume_operation_id: c.consumed.request.operation_id.clone(),
            consume_digest: c
                .consumed
                .digest_for(&c.reservation, &c.extension, &c.continuation)
                .map_err(invalid)?,
            plan_digest: c
                .reservation
                .request
                .construction
                .plan
                .digest()
                .map_err(invalid)?,
            common_context_digest: c
                .reservation
                .request
                .construction
                .plan
                .common_context_digest
                .clone(),
            invocation_digest: c.reservation.request.invocation_digest().map_err(invalid)?,
            checkpoint_origin_digest: input.checkpoint_origin.digest().map_err(invalid)?,
        };
        let manual = match &h
            .owner_control_request(&format!(
                "manual-roster-extend-v2-{}",
                c.extension.digest().map_err(invalid)?
            ))
            .ok_or(crate::Error::ReviewMismatch)?
            .control
        {
            OwnerControl::ExtendManualRosterEnrollmentV2 { record } => {
                BornNamedManualParentV1::RosterV2 {
                    record: *record.clone(),
                }
            }
            _ => return Err(crate::Error::ReviewMismatch),
        };
        let origin = BornNamedRecipientOriginV1 {
            version: 1,
            request: BornOfflineReservationRequestV1 {
                version: 1,
                enrollment_digest: e.enrollment.digest().map_err(invalid)?,
                artifact_binding_digest: artifacts.binding.digest().map_err(invalid)?,
                construction_link: link,
                reservation: reservation.clone(),
            },
            enrollment: e.clone(),
            artifacts: artifacts.clone(),
            birth: h
                .pending_birth_commit()
                .ok_or(crate::Error::ReviewMismatch)?
                .clone(),
            manual_parent: manual,
            signer_genesis: actual.genesis().clone(),
            parent_history_digest: h.history_digest().map_err(invalid)?,
            parent_head: h.snapshot().head.clone(),
            checkpoint_origin: input.checkpoint_origin,
            checkpoint_receipt,
        };
        let own_expectations = NamedRecipientOwnExpectationsV1 {
            schema_version: 1,
            full_viewing_key_digest: hex::encode(Sha256::digest(own_policy.own_fvk.to_bytes())),
            manifest_digest: hex::encode(own_policy.manifest_digest),
            anchor: hex::encode(own_policy.anchor),
            expiry_height: own_policy.expiry_height,
            maximum_selected_net_debit_zatoshis: own_policy.maximum_selected_net_debit_zatoshis,
            exact_selected_net_debit_zatoshis: own_policy.exact_selected_net_debit_zatoshis,
            declared_fee_share_zatoshis: own_policy.declared_fee_share_zatoshis,
            exact_transaction_fee_zatoshis: own_policy.exact_transaction_fee_zatoshis,
            own_inputs: own_policy
                .own_inputs
                .iter()
                .map(|i| {
                    Ok(NamedRecipientOwnInputV1 {
                        action_index: i.action_index.try_into().map_err(invalid)?,
                        nullifier: hex::encode(i.nullifier),
                        value_zatoshis: i.value_zatoshis,
                    })
                })
                .collect::<crate::Result<_>>()?,
            outputs: own_policy
                .outputs
                .iter()
                .map(|o| {
                    Ok(NamedRecipientOwnOutputV1 {
                        action_index: o.action_index.try_into().map_err(invalid)?,
                        receiver_hex: hex::encode(o.receiver.to_raw_address_bytes()),
                        value_zatoshis: o.value_zatoshis,
                        memo_hex: hex::encode(o.memo),
                        purpose: match o.purpose {
                            OwnOutputPurpose::OwnReturn => NamedRecipientOutputPurposeV1::OwnReturn,
                            OwnOutputPurpose::Recipient => NamedRecipientOutputPurposeV1::Recipient,
                            OwnOutputPurpose::PeerReturnUnverified => {
                                NamedRecipientOutputPurposeV1::PeerReturnUnverified
                            }
                        },
                    })
                })
                .collect::<crate::Result<_>>()?,
        };
        let admission = OfflineAdmissionExportPlan {
            message_id: message_id("born-admission", &terms.authorization_id),
            sequence: 0,
            issued_at_unix_seconds: issued_second.try_into().map_err(invalid)?,
            expires_at_unix_seconds: last_second.try_into().map_err(invalid)?,
            purpose: "Exact original born admission, not a payment".into(),
            persistence_warning: "Retain original ciphertext; never resequence or renew".into(),
            sender_id: format!("offline-admission:{}", terms.offline_policy_digest),
            recipient_id: format!("offline-admission:{}", terms.offline_signer_key_digest),
            sender_key_fingerprint: transport_fingerprint(&p.witness_transport_public_key),
            recipient_key_fingerprint: transport_fingerprint(&p.transport_public_key),
        };
        let proposed = NamedRecipientOriginalRecordV1 {
            schema_version: 1,
            reference: String::new(),
            profile_ref: p.reference.clone(),
            terms,
            original_artifact_digest: origin.checkpoint_origin.proved_artifact_digest.clone(),
            canonical_artifact_digest: package.statement.recipient_artifact_digest.clone(),
            transformation_digest: input.expected_transformation_digest,
            named_assertion_digest: hex::encode(Sha256::digest(
                package.statement.canonical_bytes().map_err(invalid)?,
            )),
            assertion_package_digest: package_digest,
            validity_not_before_ms: scope.original_validity_not_before_ms,
            validity_expires_ms: scope.original_validity_expires_ms,
            original_request_digest: scope.original_request_digest.clone(),
            reservation_request: reservation,
            reservation_request_digest: String::new(),
            admission_export_template: admission,
            own_policy_digest: own_policy.policy_commitment(),
            own_expectations,
            born_origin: Some(origin),
        };
        let outgoing = NamedIntentExportTemplate {
            order: MessageOrder {
                message_id: message_id("born-intent", &proposed.terms.authorization_id),
                sequence: 0,
                issued_at: Timestamp::from_unix_seconds(
                    (request_start / 1000).try_into().map_err(invalid)?,
                )
                .map_err(invalid)?,
                expires_at: Timestamp::from_unix_seconds(last_second.try_into().map_err(invalid)?)
                    .map_err(invalid)?,
            },
            purpose: "Original born request, subject to separate native consent".into(),
            persistence_warning: "Keep exact original request and uncertain outcomes".into(),
        };
        actual.check(native)?;
        self.check_current(actual.journal(), session)?;
        op.check().map_err(invalid)?;
        Ok(BornNamedRecipientOriginalInputs {
            checkpoint_envelope: EncryptedEnvelope::from_bytes(checkpoint.as_bytes().to_vec())
                .map_err(invalid)?,
            original: NamedRecipientOriginalInputs {
                proposed,
                own_policy,
                proposed_policy: e.enrollment.policy.clone(),
                assertion_envelope: EncryptedEnvelope::from_bytes(assertion.as_bytes().to_vec())
                    .map_err(invalid)?,
                outgoing,
                now: Timestamp::from_unix_seconds(
                    (request_start / 1000).try_into().map_err(invalid)?,
                )
                .map_err(invalid)?,
            },
        })
    }
}

/// Exact identifiers of an actually retained and separately exported return.
/// Inert historical references only, not a live history/dispatch capability.
#[derive(Clone)]
pub struct OriginalNamedReturnReferencesV1 {
    pub authorization_id: String,
    pub original_ref: String,
    pub born_origin_digest: String,
}
