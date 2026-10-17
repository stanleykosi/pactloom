//! Actual native Host request-only producer for the ephemeral joined harness.
//! Registered only under cfg(test). Public selection bytes choose limits, never
//! a Host identity/source, signer record, native decision or current permission.
use super::*;
use std::{path::Path, time::Instant};
use wholepact_signer_origin::PendingNativeManualPair;

pub(in crate::host) struct PreparedJoinedInitialIntent<'host> {
    owners: InitialOwners<'host>,
    account_id: String,
    review_digest: String,
    intent_digest: String,
    approval: PublicationApproval,
    pair_approval: PublicationApproval,
    deadline: Instant,
}
pub(in crate::host) struct PendingJoinedInitialIntent<'host> {
    owners: InitialOwners<'host>,
    review_digest: String,
    approval: PublicationApproval,
    deadline: Instant,
    pairing: PendingNativeManualPair,
}
impl<'host> PreparedJoinedInitialIntent<'host> {
    pub(in crate::host) fn prepare(
        host: &'host Host,
        agreement_id: &str,
        operation_id: String,
        account_id: String,
        selection_bytes: &[u8],
    ) -> Result<Self> {
        if selection_bytes.len() > 131_072 {
            return Err(Error::Invalid);
        }
        require_account_claim(&account_id)?;
        let selection: ManualScopeSelection =
            wholepact_core::parse_typed_json(selection_bytes).map_err(|_| Error::Invalid)?;
        let owners = host.prepare_manual_intent(agreement_id, operation_id, selection)?;
        owners.check_current()?;
        let intent_digest = owners.intent.digest().map_err(|_| Error::Invalid)?;
        let review_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:synthetic-joined-host-first-intent-review:v1",
            &(&owners.intent, &account_id),
        )
        .map_err(|_| Error::Invalid)?;
        let approval = host.terminal.approve_publication_reviewed(&owners.history_review, &review_digest, &format!(
            "SYNTHETIC JOINED TEST: disclose this actual Host-bound request-only first-account intent to the actual retained ephemeral signer process. No account fields, generation, Store identity or prior roster are supplied by the test as authority. Nothing grants viewing, construction, signing or financial permission. This is controller qualification, not attended consent. Exact account claim: {}. Exact intent: {}", account_id, serde_json::to_string_pretty(&owners.intent)?,
        ))?;
        let pair_approval = host.terminal.approve_publication_reviewed(&owners.history_review, &review_digest,
            "SYNTHETIC JOINED TEST: approve the exact bounded request-only pairing metadata to this original test signer. The actual image pin and ordinary authenticated IPC remain mandatory; no production install pin is replaced.")?;
        let deadline = owners
            .history_review
            .deadline()
            .min(approval.deadline())
            .min(pair_approval.deadline());
        owners.check_current()?;
        Ok(Self {
            owners,
            account_id,
            review_digest,
            intent_digest,
            approval,
            pair_approval,
            deadline,
        })
    }
    pub(in crate::host) fn intent(&self) -> &HostManualEnrollmentIntent {
        &self.owners.intent
    }
    pub(in crate::host) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(in crate::host) fn begin_pair(
        self,
        provider: InstalledSignerProvider,
        endpoint: &Path,
    ) -> Result<PendingJoinedInitialIntent<'host>> {
        let Self {
            owners,
            account_id,
            review_digest,
            intent_digest,
            approval,
            pair_approval,
            deadline,
        } = self;
        owners.check_current()?;
        approval.check()?;
        let scope = PairScope {
            account_id,
            agreement_id: owners.intent.scope.agreement_id.clone(),
            participant_id: owners.intent.scope.participant_id.clone(),
            manifest_digest: intent_digest,
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        let pairing = pair_approval.commit(
            &review_digest,
            || owners.check_current(),
            |_| {
                NativeManualClient::begin_pair_before(
                    provider,
                    endpoint,
                    "wholepact-native-manual-enrollment",
                    scope,
                    deadline,
                )
                .map_err(|_| Error::Permission)
            },
        )?;
        Ok(PendingJoinedInitialIntent {
            owners,
            review_digest,
            approval,
            deadline,
            pairing,
        })
    }
}
impl PendingJoinedInitialIntent<'_> {
    /// Return only the actual client to keep its launcher channel alive through
    /// the separate signer export phase. This grants no further Host operation.
    pub(in crate::host) fn submit(self) -> Result<NativeManualClient> {
        let Self {
            owners,
            review_digest,
            approval,
            deadline,
            pairing,
        } = self;
        let client = pairing
            .finish_checked(|| {
                owners
                    .check_current()
                    .map_err(|_| wholepact_signer_origin::Error::Permission)
            })
            .map_err(|_| Error::Permission)?;
        approval.commit(
            &review_digest,
            || owners.check_current(),
            |_| {
                client
                    .submit_enrollment_intent_before(&owners.intent, deadline)
                    .map_err(|_| Error::Permission)
            },
        )?;
        drop(owners);
        Ok(client)
    }
}

pub(in crate::host) struct PreparedJoinedInitialPublication<'host> {
    prepared: PreparedManualEnrollment<'host>,
    extension: wholepact_authority::manual_enrollment::ManualEnrollmentExtension,
    request_approval: PublicationApproval,
    pair_approval: PublicationApproval,
    review_digest: String,
    intent_digest: String,
    deadline: Instant,
}
pub(in crate::host) struct PendingJoinedInitialPublication<'host> {
    prepared: PreparedManualEnrollment<'host>,
    extension: wholepact_authority::manual_enrollment::ManualEnrollmentExtension,
    request_approval: PublicationApproval,
    review_digest: String,
    deadline: Instant,
    pairing: PendingNativeManualPair,
}
impl<'host> PreparedJoinedInitialPublication<'host> {
    pub(in crate::host) fn prepare(
        host: &'host Host,
        extension: wholepact_authority::manual_enrollment::ManualEnrollmentExtension,
        key: &str,
    ) -> Result<Self> {
        host.require_manual_session()?;
        extension.validate().map_err(|_| Error::Invalid)?;
        let request = HostManualEnrollmentRequest {
            terms: extension.terms.clone(),
        };
        let intent = HostManualEnrollmentIntent {
            version: 1,
            operation_id: request.terms.operation_id.clone(),
            host: request.terms.host.clone(),
            scope: request.terms.scope.clone(),
        };
        let intent_digest = intent.digest().map_err(|_| Error::Invalid)?;
        let review_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:synthetic-joined-first-publication-disclosure:v1",
            &(&request, &extension.enrollment_ref, &intent_digest),
        )
        .map_err(|_| Error::Invalid)?;
        let request_approval = host.terminal.approve_publication(&review_digest, &format!(
            "SYNTHETIC JOINED TEST: request this actual first-account audit from its separately retained native signer. Exact original enrollment: {}. Request: {}. Only the authenticated current lower lease and actual Store compare-and-append can retain the first audit. No roster predecessor, native decision, viewing permission or financial authority is fabricated; no original deadline is renewed.", extension.enrollment_ref, serde_json::to_string_pretty(&request)?,
        ))?;
        let pair_approval = host.terminal.approve_publication(&review_digest,
            "SYNTHETIC JOINED TEST: approve the finite original first-account pairing metadata to the pinned actual test signer process. This changes no installation trust or financial qualification gate.")?;
        let prepared = host.prepare_manual_enrollment(&request, key)?;
        let deadline = prepared
            .source
            .history_review
            .deadline()
            .min(prepared.approval.deadline())
            .min(request_approval.deadline())
            .min(pair_approval.deadline());
        prepared.source.check_current()?;
        prepared.approval.check()?;
        Ok(Self {
            prepared,
            extension,
            request_approval,
            pair_approval,
            review_digest,
            intent_digest,
            deadline,
        })
    }
    pub(in crate::host) fn request(&self) -> &HostManualEnrollmentRequest {
        &self.prepared.source.request
    }
    pub(in crate::host) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(in crate::host) fn begin_pair(
        self,
        provider: InstalledSignerProvider,
        endpoint: &Path,
    ) -> Result<PendingJoinedInitialPublication<'host>> {
        let Self {
            prepared,
            extension,
            request_approval,
            pair_approval,
            review_digest,
            intent_digest,
            deadline,
        } = self;
        prepared.source.check_current()?;
        prepared.approval.check()?;
        let terms = &prepared.source.request.terms;
        let scope = PairScope {
            account_id: terms.identity.account_id.clone(),
            agreement_id: terms.scope.agreement_id.clone(),
            participant_id: terms.scope.participant_id.clone(),
            manifest_digest: intent_digest,
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        let pairing = pair_approval.commit(
            &review_digest,
            || prepared.source.check_current(),
            |_| {
                NativeManualClient::begin_pair_before(
                    provider,
                    endpoint,
                    "wholepact-native-manual-publication",
                    scope,
                    deadline,
                )
                .map_err(|_| Error::Permission)
            },
        )?;
        Ok(PendingJoinedInitialPublication {
            prepared,
            extension,
            request_approval,
            review_digest,
            deadline,
            pairing,
        })
    }
}
impl PendingJoinedInitialPublication<'_> {
    pub(in crate::host) fn finish(
        self,
    ) -> Result<wholepact_store::manual_enrollment::ManualAuditAppendReceipt> {
        let Self {
            prepared,
            extension,
            request_approval,
            review_digest,
            deadline,
            pairing,
        } = self;
        let client = pairing
            .finish_checked(|| {
                prepared
                    .source
                    .check_current()
                    .map_err(|_| wholepact_signer_origin::Error::Permission)
            })
            .map_err(|_| Error::Permission)?;
        prepared.approval.check()?;
        let pending = request_approval.commit(
            &review_digest,
            || prepared.source.check_current(),
            |_| {
                client
                    .begin_enrollment_before(&prepared.source.request, deadline)
                    .map_err(|_| Error::Permission)
            },
        )?;
        let lease = pending.finish().map_err(|_| Error::Permission)?;
        let actual = lease.evidence();
        if actual.enrollment_ref != extension.enrollment_ref
            || actual.witness_extension_digest != extension.digest().map_err(|_| Error::Invalid)?
            || actual.witness_extension_sequence != extension.sequence
            || actual.witness_extension_predecessor_digest != extension.predecessor_digest
        {
            return Err(Error::Authentication);
        }
        prepared.append_audit(lease)
    }
}
