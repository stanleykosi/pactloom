//! Finite test-only composition of the genuine existing-original continuation.
//! The ordinary private-file reader, actual Store/source owner and exact native
//! approvals remain mandatory. Only the retained fixture's actual pinned peer
//! replaces the command's installed-provider launch interaction.
#![cfg(all(test, feature = "synthetic-born-joined-qualification"))]

use super::*;
use std::{path::Path, time::Instant};
use wholepact_signer_origin::PendingNativeManualPair;

pub(in crate::host) struct PreparedJoinedRosterContinuationIntent<'host> {
    prepared: PreparedRosterContinuationIntent<'host>,
    request_approval: PublicationApproval,
    pair_approval: PublicationApproval,
    intent_digest: String,
    review_digest: String,
    deadline: Instant,
}

pub(in crate::host) struct PendingJoinedRosterContinuationIntent<'host> {
    prepared: PreparedRosterContinuationIntent<'host>,
    request_approval: PublicationApproval,
    review_digest: String,
    deadline: Instant,
    pairing: PendingNativeManualPair,
}

impl<'host> PreparedJoinedRosterContinuationIntent<'host> {
    /// The actual terminal asks for the exact original private signed export.
    /// This does not accept an imported replacement Host binding or predecessor.
    pub(in crate::host) fn prepare(host: &'host Host) -> Result<Self> {
        host.require_manual_session()?;
        let signed: ManualRosterEnrollmentOwnerSignatureV2 = host.read_manual_private(
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
            // Immutable lookup only, never sent as an Initial publication.
            attempt: ManualRosterPublicationAttemptV2::InitialV2 {},
        };
        let original = host.prepare_manual_roster_account_owner(
            &lookup_request.enrollment,
            &extension.account_extension.terms.operation_id,
        )?;
        let purpose = RosterAuditPurpose::ExistingOriginalContinuationV4;
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
            .map(|audit| audit.digest())
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
        let request_approval = host.terminal.approve_publication_reviewed(
            &prepared.original.source.history_review,
            &review_digest,
            &format!(
                "SYNTHETIC JOINED CONTROLLER TEST, NOT ATTENDED CONSENT. Send the SAME immutable original roster V2 intent for a later session of this exact already-retained original Host audit.\nOriginal Host audit: {}\nAccount: {}\nOriginal enrollment: {}\nOriginal intent digest: {}\n{}\nThe actual signer must authenticate its original history, then independently review, retain, sign and privately export a new continuation. Independent native witness review and a fresh publication entry follow. This does not recompute the predecessor, renew any original deadline, clear exposure, acquire a writer, or grant viewing, construction, signature or dispatch permission.",
                prepared.prior_digest.as_deref().ok_or(Error::Authentication)?,
                prepared.extension.account_extension.terms.identity.account_id,
                prepared.extension.account_extension.enrollment_ref,
                intent_digest,
                serde_json::to_string_pretty(&prepared.intent)?,
            ),
        )?;
        let pair_approval = host.terminal.approve_publication_reviewed(
            &prepared.original.source.history_review,
            &review_digest,
            "SYNTHETIC JOINED CONTROLLER TEST: approve only finite original-intent pairing metadata to the retained actual same-image pinned signer. The original Host source, Store audit and earliest native deadline remain mandatory. No viewing data, transaction witness, construction, proof, signature release, dispatch or automatic future use is approved.",
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
        Ok(Self {
            prepared,
            request_approval,
            pair_approval,
            intent_digest,
            review_digest,
            deadline,
        })
    }

    pub(in crate::host) fn intent(&self) -> &HostManualRosterEnrollmentIntentV2 {
        &self.prepared.intent
    }

    pub(in crate::host) fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(in crate::host) fn begin_pair(
        self,
        provider: InstalledSignerProvider,
        endpoint: &Path,
    ) -> Result<PendingJoinedRosterContinuationIntent<'host>> {
        let Self {
            prepared,
            request_approval,
            pair_approval,
            intent_digest,
            review_digest,
            deadline,
        } = self;
        prepared.check_current()?;
        request_approval.check()?;
        let scope = PairScope {
            account_id: prepared
                .extension
                .account_extension
                .terms
                .identity
                .account_id
                .clone(),
            agreement_id: prepared.intent.account_intent.scope.agreement_id.clone(),
            participant_id: prepared.intent.account_intent.scope.participant_id.clone(),
            manifest_digest: intent_digest,
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        let pairing = pair_approval.commit(
            &review_digest,
            || prepared.check_current(),
            |_| {
                NativeManualClient::begin_pair_before(
                    provider,
                    endpoint,
                    "wholepact-native-roster-continuation-intent-v2",
                    scope,
                    deadline,
                )
                .map_err(|_| Error::Permission)
            },
        )?;
        Ok(PendingJoinedRosterContinuationIntent {
            prepared,
            request_approval,
            review_digest,
            deadline,
            pairing,
        })
    }
}

impl PendingJoinedRosterContinuationIntent<'_> {
    /// Keep only the actual client's parent channel through genuine signer
    /// export. Neither old Host approval nor a publication lease is extended.
    pub(in crate::host) fn submit(self) -> Result<NativeManualClient> {
        let Self {
            prepared,
            request_approval,
            review_digest,
            deadline,
            pairing,
        } = self;
        let client = pairing
            .finish_checked(|| {
                prepared
                    .check_current()
                    .map_err(|_| wholepact_signer_origin::Error::Permission)
            })
            .map_err(|_| Error::Permission)?;
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
        Ok(client)
    }
}
