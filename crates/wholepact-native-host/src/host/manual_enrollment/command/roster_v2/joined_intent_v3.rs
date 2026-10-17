//! Actual native Host request-only producer for the ephemeral joined harness.
//! Registered only under cfg(test). Public selection bytes choose limits, never
//! a Host identity/source, signer record, native decision or current permission.
use super::*;
use std::{path::Path, time::Instant};
use wholepact_signer_origin::PendingNativeManualPair;

pub(in crate::host) struct PreparedJoinedRosterIntent<'host> {
    owners: RosterInitialOwners<'host>,
    account_id: String,
    review_digest: String,
    intent_digest: String,
    approval: PublicationApproval,
    pair_approval: PublicationApproval,
    deadline: Instant,
}
pub(in crate::host) struct PendingJoinedRosterIntent<'host> {
    owners: RosterInitialOwners<'host>,
    review_digest: String,
    approval: PublicationApproval,
    deadline: Instant,
    pairing: PendingNativeManualPair,
}
impl<'host> PreparedJoinedRosterIntent<'host> {
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
        let owners = host.prepare_manual_roster_intent(agreement_id, operation_id, selection)?;
        owners.check_current()?;
        let members = owners.engine.members(host.access()?)?;
        let intent_digest = owners.intent.digest().map_err(|_| Error::Invalid)?;
        let review_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:synthetic-joined-host-roster-intent-review:v3",
            &(&owners.intent, members, &account_id),
        )
        .map_err(|_| Error::Invalid)?;
        let approval = host.terminal.approve_publication_reviewed(&owners.history_review, &review_digest, &format!(
            "SYNTHETIC JOINED TEST: disclose this actual Host-bound request-only additional-account intent to the actual retained ephemeral signer process. No account fields, generation, Store identity or prior roster are supplied by the test as authority. Nothing grants viewing, construction, signing or financial permission. This is controller qualification, not attended consent. Exact account claim: {}. Exact intent: {}", account_id, serde_json::to_string_pretty(&owners.intent)?,
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
    pub(in crate::host) fn intent(&self) -> &HostManualRosterEnrollmentIntentV2 {
        &self.owners.intent
    }
    pub(in crate::host) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(in crate::host) fn begin_pair(
        self,
        provider: InstalledSignerProvider,
        endpoint: &Path,
    ) -> Result<PendingJoinedRosterIntent<'host>> {
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
            agreement_id: owners.intent.account_intent.scope.agreement_id.clone(),
            participant_id: owners.intent.account_intent.scope.participant_id.clone(),
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
                    "wholepact-native-manual-roster-enrollment-v2",
                    scope,
                    deadline,
                )
                .map_err(|_| Error::Permission)
            },
        )?;
        Ok(PendingJoinedRosterIntent {
            owners,
            review_digest,
            approval,
            deadline,
            pairing,
        })
    }
}
impl PendingJoinedRosterIntent<'_> {
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
                    .submit_roster_enrollment_intent_v2_before(&owners.intent, deadline)
                    .map_err(|_| Error::Permission)
            },
        )?;
        drop(owners);
        Ok(client)
    }
}
