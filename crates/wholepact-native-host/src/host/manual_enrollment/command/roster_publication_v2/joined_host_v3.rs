//! Synthetic joined-harness composition, not an alternative permission issuer.
//! Every Host owner below is prepared by the ordinary native path. The caller
//! supplies only actual signer-produced public records and a pinned running
//! synthetic signer process. No native decision, lease or retained input is
//! reconstructed from a DTO. This entire child is registered only for tests.
use super::*;
use std::{path::Path, time::Instant};
use wholepact_signer_origin::PendingNativeManualPair;

type Retained<'host> =
    crate::host::financial::manual_roster_inventory_setup_v2::RetainedRosterCandidateInputsV2<
        'host,
    >;

pub(in crate::host) struct PreparedJoinedRosterPublication<'host> {
    host: &'host Host,
    prepared: PreparedRosterPublication<'host>,
    inventory: Option<inventory_v2::PreparedInventory>,
    request_approval: PublicationApproval,
    pair_approval: PublicationApproval,
    exact_digest: String,
    deadline: Instant,
}
pub(in crate::host) struct PendingJoinedRosterPublication<'host> {
    host: &'host Host,
    prepared: PreparedRosterPublication<'host>,
    inventory: Option<inventory_v2::PreparedInventory>,
    request_approval: PublicationApproval,
    exact_digest: String,
    deadline: Instant,
    pairing: PendingNativeManualPair,
}
#[derive(Clone, Copy)]
pub(in crate::host) enum JoinedRosterPreparationV3 {
    AuditOnly,
    CommonContextRetentionV2,
}

impl<'host> PreparedJoinedRosterPublication<'host> {
    /// The selection files and every private approval are still read by the
    /// actual Host terminal path. The input is correlation, not signer authority.
    pub(in crate::host) fn prepare(
        host: &'host Host,
        request: HostManualRosterPublicationRequestV2,
        extension: ManualRosterEnrollmentExtensionV2,
        key: &str,
        existing_original: bool,
        preparation: JoinedRosterPreparationV3,
    ) -> Result<Self> {
        host.require_manual_session()?;
        let purpose = if existing_original {
            RosterAuditPurpose::ExistingOriginalContinuationV4
        } else {
            RosterAuditPurpose::InitialPublicationV3
        };
        let continuation = matches!(
            request.attempt,
            ManualRosterPublicationAttemptV2::ContinuationV2 { .. }
        );
        let mode = match preparation {
            JoinedRosterPreparationV3::AuditOnly => PreparationMode::AuditOnly,
            JoinedRosterPreparationV3::CommonContextRetentionV2 => {
                PreparationMode::InventoryAndCommonContextRetainedSelection
            }
        };
        mode.require_purpose(continuation, purpose)?;
        let prepared = host.prepare_roster_publication(request, extension, purpose, key)?;
        let inventory = if mode.retains_inputs() {
            Some(inventory_v2::prepare(host, &prepared, mode.selection())?)
        } else {
            None
        };
        let exact_digest = prepared.request.digest().map_err(|_| Error::Invalid)?;
        let request_approval = host.terminal.approve_publication_reviewed(
            &prepared.original.source.history_review,
            &exact_digest,
            &format!("SYNTHETIC JOINED TEST: send ONLY this actual prepared roster request to the separately retained test signer over authenticated ordinary IPC. All Host identity, agreement, original ancestry, attachment and selection authority remains checked by the actual source owners. This is test-controller approval, not attended consent. Request: {}", serde_json::to_string_pretty(&prepared.request)?),
        )?;
        let pair_approval = host.terminal.approve_publication_reviewed(
            &prepared.original.source.history_review,
            &exact_digest,
            "SYNTHETIC JOINED TEST: approve the exact bounded pairing metadata for this original roster publication to the actual same-process-image pinned ephemeral signer. No production installation trust or financial qualification gate is changed.",
        )?;
        let mut deadline = prepared
            .original
            .source
            .history_review
            .deadline()
            .min(prepared.original.approval.deadline())
            .min(prepared.approval.deadline())
            .min(request_approval.deadline())
            .min(pair_approval.deadline());
        if let Some(owner) = &inventory {
            owner.check_before(&prepared)?;
            deadline = deadline.min(owner.deadline());
        }
        prepared.check_before()?;
        Ok(Self {
            host,
            prepared,
            inventory,
            request_approval,
            pair_approval,
            exact_digest,
            deadline,
        })
    }
    pub(in crate::host) fn request(&self) -> &HostManualRosterPublicationRequestV2 {
        &self.prepared.request
    }
    pub(in crate::host) fn retention_operation_id(&self) -> Option<&str> {
        self.inventory
            .as_ref()
            .and_then(|i| i.synthetic_retention_operation_id())
    }
    pub(in crate::host) fn inventory_parts(
        &self,
    ) -> Option<(
        &wholepact_core::manual_roster_inventory_v2::ManualRosterInventoryScopeV2,
        &str,
    )> {
        self.inventory
            .as_ref()
            .map(|i| i.synthetic_exact_request_parts())
    }
    pub(in crate::host) fn selection_parts(&self) -> Option<(&wholepact_core::manual_roster_candidate_selection_v2::ManualRosterCandidateSelectionScopeV2, &str)>{
        self.inventory
            .as_ref()
            .and_then(|i| i.synthetic_selection_parts())
    }
    pub(in crate::host) fn deadline(&self) -> Instant {
        self.deadline
    }
    /// The supplied provider must itself authenticate the actual running image.
    /// An arbitrary endpoint or record cannot construct the resulting client.
    pub(in crate::host) fn begin_pair(
        self,
        provider: InstalledSignerProvider,
        endpoint: &Path,
    ) -> Result<PendingJoinedRosterPublication<'host>> {
        self.prepared.check_before()?;
        let terms = &self.prepared.request.enrollment.terms;
        let scope = PairScope {
            account_id: terms.identity.account_id.clone(),
            agreement_id: terms.scope.agreement_id.clone(),
            participant_id: terms.scope.participant_id.clone(),
            manifest_digest: self.exact_digest.clone(),
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        let Self {
            host,
            prepared,
            inventory,
            request_approval,
            pair_approval,
            exact_digest,
            deadline,
        } = self;
        let pairing = pair_approval.commit(
            &exact_digest,
            || prepared.check_before(),
            |_| {
                NativeManualClient::begin_pair_before(
                    provider,
                    endpoint,
                    "wholepact-native-roster-publication-v2",
                    scope,
                    deadline,
                )
                .map_err(|_| Error::Permission)
            },
        )?;
        // The spent pairing approval cannot be reused. The remaining concrete
        // approvals and actual source stay owned until the ordinary IPC finishes.
        Ok(PendingJoinedRosterPublication {
            host,
            prepared,
            inventory,
            request_approval,
            exact_digest,
            deadline,
            pairing,
        })
    }
}

impl<'host> PendingJoinedRosterPublication<'host> {
    pub(in crate::host) fn finish(self) -> Result<Option<Retained<'host>>> {
        let Self {
            host,
            prepared,
            inventory,
            request_approval,
            exact_digest,
            deadline,
            pairing,
        } = self;
        let client = roster_trace!(
            JoinedPairFinish,
            pairing
                .finish_checked(|| {
                    prepared
                        .check_before()
                        .map_err(|_| wholepact_signer_origin::Error::Permission)
                })
                .map_err(|_| Error::Permission)
        )?;
        let pending = roster_trace!(
            JoinedRequestBegin,
            request_approval.commit(
                &exact_digest,
                || prepared.check_before(),
                |_| {
                    client
                        .begin_roster_enrollment_v2_before(&prepared.request, deadline)
                        .map_err(|_| Error::Permission)
                },
            )
        )?;
        let lease = roster_trace!(
            JoinedLeaseFinish,
            pending.finish().map_err(|_| Error::Permission)
        )?;
        if let Some(inventory) = inventory {
            roster_trace!(JoinedInventoryCheck, inventory.check_before(&prepared))?;
            let (_receipt, committed) =
                roster_trace!(JoinedAuditAppend, prepared.append_owned(lease))?;
            roster_trace!(JoinedInventoryRun, inventory.run(host, client, &committed))
        } else {
            roster_trace!(JoinedAuditAppend, prepared.append(lease))?;
            Ok(None)
        }
    }
}
