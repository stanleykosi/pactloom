//! Original-intent launch for a separately reviewed roster V2 continuation.
//! Parent owner checks authenticate the live Host. This never creates a roster
//! position, witness attempt, publication lease or approval from imported data.
use super::*;
#[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
pub(super) mod joined_continuation_v3;
use wholepact_signer_origin::manual_roster_v2::HostManualRosterEnrollmentIntentV2;

struct PreparedRosterContinuationIntent<'host> {
    original: PreparedManualEnrollment<'host>,
    extension: ManualRosterEnrollmentExtensionV2,
    lookup_request: HostManualRosterPublicationRequestV2,
    intent: HostManualRosterEnrollmentIntentV2,
    purpose: RosterAuditPurpose,
    prior_digest: Option<String>,
}
impl PreparedRosterContinuationIntent<'_> {
    fn read_original(
        &self,
    ) -> Result<Option<wholepact_store::manual_enrollment::ManualEnrollmentAdditionalPublicationV3>>
    {
        let source = &self.original.source;
        // The same immutable-identity check used by actual V3/V4 publication.
        // The inert lookup attempt below is never sent as a publication request.
        source
            .host
            .engine
            .manual_roster_request_original(
                source.host.access()?,
                &source.engine,
                &self.lookup_request,
                &self.extension.account_extension.enrollment_ref,
                &self
                    .extension
                    .account_extension
                    .digest()
                    .map_err(|_| Error::Invalid)?,
                &self.extension.digest().map_err(|_| Error::Invalid)?,
                &self.extension.signer_roster_record_digest,
            )
            .map_err(Into::into)
    }
    fn check_current(&self) -> Result<()> {
        self.original.source.check_current()?;
        self.original.approval.check()?;
        self.extension.validate().map_err(|_| Error::Invalid)?;
        self.intent
            .matches_terms(
                &self.extension.account_extension.terms,
                &self.extension.roster,
            )
            .map_err(|_| Error::Authentication)?;
        let current = self
            .read_original()?
            .as_ref()
            .map(|a| a.digest())
            .transpose()?;
        require_intent_original(
            self.purpose,
            self.prior_digest.as_deref(),
            current.as_deref(),
        )
    }
}

/// Inert decision-table validation shared by the real owner and negative tests.
/// It cannot construct any approval or change the roster head.
fn require_intent_original(
    purpose: RosterAuditPurpose,
    captured: Option<&str>,
    current: Option<&str>,
) -> Result<()> {
    if captured != current {
        return Err(Error::Authentication);
    }
    match purpose {
        RosterAuditPurpose::InitialPublicationV3 if captured.is_none() => Ok(()),
        RosterAuditPurpose::ExistingOriginalContinuationV4 if captured.is_some() => Ok(()),
        _ => Err(Error::Authentication),
    }
}
fn original_intent(
    extension: &ManualRosterEnrollmentExtensionV2,
) -> Result<HostManualRosterEnrollmentIntentV2> {
    extension.validate().map_err(|_| Error::Invalid)?;
    let terms = &extension.account_extension.terms;
    let intent = HostManualRosterEnrollmentIntentV2 {
        version: 2,
        account_intent: HostManualEnrollmentIntent {
            version: 1,
            operation_id: terms.operation_id.clone(),
            host: terms.host.clone(),
            scope: terms.scope.clone(),
        },
        // Retain this exact original predecessor even when later members exist.
        // No call to manual_roster_intent_target or current-head reconstruction.
        roster: extension.roster.clone(),
    };
    intent
        .matches_terms(terms, &extension.roster)
        .map_err(|_| Error::Invalid)?;
    Ok(intent)
}
impl Host {
    pub(in crate::host) fn manual_roster_initial_continuation_intent_v2_command(
        &self,
    ) -> Result<()> {
        self.roster_continuation_intent_v2(RosterAuditPurpose::InitialPublicationV3)
    }
    pub(in crate::host) fn manual_roster_continue_intent_v2_command(&self) -> Result<()> {
        self.roster_continuation_intent_v2(RosterAuditPurpose::ExistingOriginalContinuationV4)
    }
    fn roster_continuation_intent_v2(&self, purpose: RosterAuditPurpose) -> Result<()> {
        self.require_manual_session()?;
        let signed: ManualRosterEnrollmentOwnerSignatureV2 = self.read_manual_private(
            "Exact ORIGINAL private roster owner-signature JSON file: ",
            "reviewing unchanged original account, Host generation and roster predecessor before an independently approved continuation",
        )?;
        let extension = signed.extension;
        let intent = original_intent(&extension)?;
        let lookup_request = HostManualRosterPublicationRequestV2 {
            version: 2,
            enrollment: HostManualEnrollmentRequest {
                terms: extension.account_extension.terms.clone(),
            },
            roster: extension.roster.clone(),
            // Only a lookup of immutable original fields. This placeholder is
            // never sent to the signer, written, or treated as admission evidence.
            attempt: ManualRosterPublicationAttemptV2::InitialV2 {},
        };
        // Actual original account/Host/capsule owner and native disclosure consent.
        // Its correlation key is used only for this in-memory native review;
        // continuation preparation makes no Store command or idempotency write.
        let original = self.prepare_manual_roster_account_owner(
            &lookup_request.enrollment,
            &extension.account_extension.terms.operation_id,
        )?;
        let mut prepared = PreparedRosterContinuationIntent {
            original,
            extension,
            lookup_request,
            intent,
            purpose,
            prior_digest: None,
        };
        prepared.prior_digest = prepared
            .read_original()?
            .as_ref()
            .map(|a| a.digest())
            .transpose()?;
        prepared.check_current()?;
        let intent_digest = prepared.intent.digest().map_err(|_| Error::Invalid)?;
        let review_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:native-host-roster-continuation-intent-review:v2",
            &(
                &prepared.intent,
                &prepared.extension,
                purpose,
                &prepared.prior_digest,
                prepared.original.source.engine.agreement_record_digest(),
                prepared.original.source.engine.agreement_revision(),
                prepared.original.source.engine.owner_client_id(),
            ),
        )
        .map_err(|_| Error::Invalid)?;
        let purpose_text = match purpose {
            RosterAuditPurpose::InitialPublicationV3 => {
                "explicit first Host save after an interrupted or expired original attempt; no prior Host audit exists"
            }
            RosterAuditPurpose::ExistingOriginalContinuationV4 => {
                "a later session for the exact already-retained original Host audit"
            }
        };
        let request_approval = self.terminal.approve_publication_reviewed(
            &prepared.original.source.history_review, &review_digest, &format!(
                "Send the SAME immutable original roster V2 intent for {purpose_text}.\nOriginal prior Host audit: {}\nAccount: {}\nOriginal account enrollment: {}\nExact original V2 roster intent digest: {}\n{}\nThe installed signer must authenticate its own existing attempted/completed history, then separately review, retain, sign and privately export a new roster-bound session continuation. Independent witness-owner approval and a fresh publication entry are required afterward. This does not create another enrollment, recompute a roster predecessor, change an original deadline, clear exposure, authorize a writer acquisition, or return financial permission.",
                prepared.prior_digest.as_deref().unwrap_or("absent: first-save preparation only"),
                prepared.extension.account_extension.terms.identity.account_id,
                prepared.extension.account_extension.enrollment_ref, intent_digest,
                serde_json::to_string_pretty(&prepared.intent)?,
            ),
        )?;
        let pair_approval = self.terminal.approve_publication_reviewed(
            &prepared.original.source.history_review, &review_digest, &format!(
                "Approve finite original-intent pairing metadata for roster continuation preparation.\nAccount: {}\nAgreement/participant: {}/{}\nEXACT original V2 intent digest: {}\nComplete all terminal input now, then stay in the separate signer window. No viewing key, transaction witness, construction, proof, signature release, dispatch or automatic future use is authorized. The earliest original native deadline survives launch and pairing delays.",
                prepared.extension.account_extension.terms.identity.account_id,
                prepared.intent.account_intent.scope.agreement_id,
                prepared.intent.account_intent.scope.participant_id, intent_digest,
            ),
        )?;
        let deadline = prepared
            .original
            .source
            .history_review
            .deadline()
            .min(prepared.original.approval.deadline())
            .min(request_approval.deadline())
            .min(pair_approval.deadline());
        prepared.check_current()?;
        request_approval.check()?;
        pair_approval.check()?;
        let provider = InstalledSignerProvider::load().map_err(|_| Error::Permission)?;
        provider.launch_native().map_err(|_| Error::Permission)?;
        let endpoint = wait_manual_endpoint_before(&provider, deadline)?;
        prepared.check_current()?;
        request_approval.check()?;
        pair_approval.check()?;
        let pending = pair_approval.commit(
            &review_digest,
            || prepared.check_current(),
            |_| {
                NativeManualClient::begin_pair_before(
                    provider,
                    &endpoint,
                    "wholepact-native-roster-continuation-intent-v2",
                    PairScope {
                        account_id: prepared
                            .extension
                            .account_extension
                            .terms
                            .identity
                            .account_id
                            .clone(),
                        agreement_id: prepared.intent.account_intent.scope.agreement_id.clone(),
                        participant_id: prepared.intent.account_intent.scope.participant_id.clone(),
                        manifest_digest: intent_digest.clone(),
                        history_read: false,
                        authorization_export: false,
                        preconstruction_export: false,
                    },
                    deadline,
                )
                .map_err(|_| Error::Permission)
            },
        )?;
        // Waiting for independent native review holds no terminal mutex or
        // publication lease. Liveness and original source are rechecked afterward.
        let client = pending.finish().map_err(|_| Error::Permission)?;
        request_approval.commit(
            &review_digest,
            || prepared.check_current(),
            |_| {
                client
                    .submit_roster_enrollment_intent_v2_before(&prepared.intent, deadline)
                    .map_err(|_| Error::Permission)
            },
        )?;
        drop(prepared);
        // Retain only the launcher's parent-channel lifetime across this wait.
        // No historical approval, Store owner, witness session, or consent is
        // extended through a later focus handoff; this is cleanup-only input.
        self.terminal.message("Exact original roster V2 intent queued. STAY IN THE SIGNER WINDOW to select the original witness, separately review/retain/sign and privately export the exact continuation. Do not acquire a new writer in this export entry. Then return here only to close the launcher channel, and complete independent witness-owner continuation review. This Host receives no export-success or authority claim.\n")?;
        let _cleanup_only = self.terminal.ask("After leaving the signer export phase, press Enter to close its request channel (cleanup only): ")?;
        drop(client);
        let next = match purpose {
            RosterAuditPurpose::InitialPublicationV3 => {
                "the explicit first-save roster continuation publication command"
            }
            RosterAuditPurpose::ExistingOriginalContinuationV4 => {
                "the existing-original roster continuation publication command"
            }
        };
        self.terminal.message(&format!("Preparation channel closed. Use {next} with the exact signed V2 continuation after separate witness-owner review. It must collect all Host input before launching a fresh signer entry. Financial and inventory/selection capabilities remain denied.\n"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preparation_purpose_cannot_adopt_or_discard_an_original() {
        let original = "a".repeat(64);
        let different = "b".repeat(64);
        require_intent_original(RosterAuditPurpose::InitialPublicationV3, None, None).unwrap();
        require_intent_original(
            RosterAuditPurpose::ExistingOriginalContinuationV4,
            Some(&original),
            Some(&original),
        )
        .unwrap();
        assert!(
            require_intent_original(
                RosterAuditPurpose::InitialPublicationV3,
                Some(&original),
                Some(&original)
            )
            .is_err()
        );
        assert!(
            require_intent_original(
                RosterAuditPurpose::ExistingOriginalContinuationV4,
                None,
                None
            )
            .is_err()
        );
        for purpose in [
            RosterAuditPurpose::InitialPublicationV3,
            RosterAuditPurpose::ExistingOriginalContinuationV4,
        ] {
            assert!(require_intent_original(purpose, None, Some(&original)).is_err());
            assert!(require_intent_original(purpose, Some(&original), None).is_err());
            assert!(require_intent_original(purpose, Some(&original), Some(&different)).is_err());
        }
    }
}
