//! Connected writer-reconciliation storage kernel. Offline execution remains
//! explicitly disabled at preparation, commit and import boundaries. No public
//! importer, DTO approval or original-consent/key-use/result manufacture exists.
use super::*;
use rusqlite::{params, types::ValueRef, Connection, OptionalExtension, Transaction};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use wholepact_authority::{
    manual_roster_construction_v2::ManualRosterConstructionHistoryRecordV2,
    offline::{OfflineAuthorizationAdmission, OfflineEnrollmentPolicy},
    OwnerControl, ReconciledAuthorityHistory, ReservationEvidenceRef, ReservationPermit,
};

pub(super) struct WriterLocalInventory {
    originals: Vec<OriginalAuthorizationEvidence>,
    remote_online: Vec<ReservationPermit>,
    offline: OfflineHistoryInventory,
    commitment: String,
    common_context_audit: CommonContextSignerAuditInventoryV1,
}
impl WriterLocalInventory {
    /// Borrowed historical review evidence; neither accessor grants mutation.
    pub(super) fn commitment(&self) -> &str {
        &self.commitment
    }
    pub(super) fn offline_history(&self) -> &OfflineHistoryInventory {
        &self.offline
    }
    /// One actual transaction, exact executable-owned schema, and all durable
    /// cells committed. Semantic origin readers additionally validate links.
    /// Other bridge/host semantics remain their owners' responsibility.
    pub(super) fn read(
        c: &Connection,
        account: &SignerAccountState,
        limits: (u64, u64),
    ) -> Result<Self> {
        if c.is_autocommit() {
            return Err(JournalError::InvalidBinding);
        }
        storage::check_account(c, account)?;
        storage::verify_schema(c)?;
        storage::require_no_unimplemented_reentry(c)?;
        Self::read_validated_cells(c, account, limits)
    }

    // This kernel is private to this module. The ordinary reader above keeps
    // its refusal. The complete transport owner below validates every reentry
    // row against full authenticated replay before exposing any branch.
    fn read_validated_cells(
        c: &Connection,
        account: &SignerAccountState,
        limits: (u64, u64),
    ) -> Result<Self> {
        named_recipient_inventory::require_absent(c)?;
        Self::read_existing_origin_cells(c, account, limits)
    }

    // Used only by the wrapper above and the restriction-only JSON renderer
    // below. The latter also retains the COMPLETE named fingerprint inventory.
    // This private branch is never returned as a writer/recovery/import plan.
    fn read_existing_origin_cells(
        c: &Connection,
        account: &SignerAccountState,
        limits: (u64, u64),
    ) -> Result<Self> {
        if c.is_autocommit() {
            return Err(JournalError::InvalidBinding);
        }
        storage::check_account(c, account)?;
        storage::verify_schema(c)?;
        storage::bounded(c, limits)?;
        let offline = offline_history::read_existing_origin_cells(c, &account.account_id)?;
        let common_context_audit = construction_audit_v3::read_all(c, &account.account_id)?;
        let mut q = c.prepare("SELECT authorization_id,reference,nonce,enrollment_ref,manifest_ref FROM signer_original_consents ORDER BY authorization_id")?;
        let mut originals = Vec::new();
        for row in q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })? {
            let (authorization, reference, nonce, enrollment, manifest) = row?;
            let original =
                storage::read_original(c, &authorization)?.ok_or(JournalError::InvalidBinding)?;
            let t = original.original_consent().terms();
            if t.account_id != account.account_id
                || original.original_consent().reference() != reference
                || t.receipt.nonce() != nonce
                || t.enrollment_ref != enrollment
                || t.accepted_manifest_ref != manifest
                || t.receipt.writer_epoch() > account.writer_epoch
            {
                return Err(JournalError::InvalidBinding);
            }
            originals.push(original);
        }
        drop(q);
        let releases: u64 =
            c.query_row("SELECT count(*) FROM signer_release_intents", [], |r| {
                r.get(0)
            })?;
        if releases != originals.len() as u64 {
            return Err(JournalError::InvalidBinding);
        }
        let original_by_id: BTreeMap<_, _> = originals
            .iter()
            .map(|o| (o.original_consent().terms().authorization_id.as_str(), o))
            .collect();
        let mut q = c.prepare("SELECT authorization_id,original_consent_ref,account_id,obligation_id,maximum_debit,payload FROM signer_remote_exposures ORDER BY authorization_id")?;
        let mut remote_online = Vec::new();
        for row in q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })? {
            let (authorization, reference, row_account, obligation, debit, raw) = row?;
            let permit: ReservationPermit = decode(raw)?;
            permit
                .matches_request(&permit.request)
                .map_err(|_| JournalError::InvalidBinding)?;
            permit
                .request
                .validate()
                .map_err(|_| JournalError::InvalidBinding)?;
            let r = &permit.request;
            if r.authorization_id != authorization
                || r.original_consent_ref != reference
                || r.account_id != account.account_id
                || row_account != account.account_id
                || r.obligation_id != obligation
                || r.maximum_debit_zatoshis.to_string() != debit
            {
                return Err(JournalError::InvalidBinding);
            }
            validate_inputs(
                c,
                "signer_remote_inputs",
                &authorization,
                &account.account_id,
                r.inputs.iter().map(|i| i.nullifier.as_str()),
            )?;
            if let Some(original) = original_by_id.get(authorization.as_str()) {
                validate_original_permit(original, &permit)?;
            }
            remote_online.push(permit);
        }
        drop(q);
        for original in &originals {
            let t = original.original_consent().terms();
            validate_inputs(
                c,
                "signer_input_reservations",
                &t.authorization_id,
                &account.account_id,
                t.input_bindings.iter().map(|i| i.nullifier.as_str()),
            )?;
            // Check the release's denormalized columns, not only its payload.
            let (reference, row_account, obligation, debit, state): (String,String,String,String,String) = c.query_row(
                "SELECT original_consent_ref,account_id,obligation_id,maximum_debit,exposure_state FROM signer_release_intents WHERE authorization_id=?1", [&t.authorization_id],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
            if reference != original.original_consent().reference()
                || row_account != account.account_id
                || obligation != t.obligation_id
                || debit != t.maximum_debit_zatoshis.to_string()
                || state != "outstanding_uncertain"
            {
                return Err(JournalError::InvalidBinding);
            }
        }
        let commitment = complete_journal_commitment(c)?;
        Ok(Self {
            originals,
            remote_online,
            offline,
            commitment,
            common_context_audit,
        })
    }
    /// Recovery is stricter than an ordinary writer handoff: every retained
    /// online original must occur in complete authenticated witness replay.
    /// The typed iterator is never a permit-only filtered continuity claim.
    #[cfg(all(
        feature = "native-ui",
        feature = "authority-signing",
        target_os = "linux"
    ))]
    pub(super) fn require_all_online_originals_replayed(
        &self,
        history: &ReconciledAuthorityHistory,
    ) -> Result<()> {
        if history
            .reservation_evidence()
            .any(|entry| matches!(entry, ReservationEvidenceRef::BornOfflineV1(_)))
        {
            return Err(JournalError::RecoveryRequired);
        }
        let online: BTreeMap<_, _> = history
            .reservation_evidence()
            .filter_map(|entry| match entry {
                ReservationEvidenceRef::OnlineV2(permit) => {
                    Some((permit.request.authorization_id.as_str(), permit))
                }
                ReservationEvidenceRef::OfflineV1(_) | ReservationEvidenceRef::BornOfflineV1(_) => {
                    None
                }
            })
            .collect();
        for original in &self.originals {
            let consent = original.original_consent();
            let permit = online
                .get(consent.terms().authorization_id.as_str())
                .ok_or(JournalError::RecoveryRequired)?;
            validate_original_permit(original, permit)?;
        }
        Ok(())
    }
}

/// Same-snapshot read-only V5 inventory. It cannot become PreparedWriterHistory,
/// a writer session, native approval or import authority.
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
pub(super) struct TransportContinuityLocalInventory {
    local: WriterLocalInventory,
    complete:
        wholepact_authority::construction_transport_handoff_v1::ConstructionHistoryWithTransportV1,
    audit: CommonContextSignerAuditInventoryV2,
}
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
impl TransportContinuityLocalInventory {
    pub(super) fn read(
        c: &Connection,
        account: &SignerAccountState,
        limits: (u64, u64),
        history: &ReconciledAuthorityHistory,
    ) -> Result<Self> {
        let complete = history
            .construction_history_with_transport_v1()
            .map_err(|_| JournalError::InvalidBinding)?;
        let local = WriterLocalInventory::read_validated_cells(c, account, limits)?;
        let audit = common_context_reentry_audit_v1::read_complete(c, &account.account_id)?;
        audit.validate_against(&complete)?;
        if audit.original != local.common_context_audit {
            return Err(JournalError::InvalidBinding);
        }
        local.require_all_online_originals_replayed(history)?;
        Ok(Self {
            local,
            complete,
            audit,
        })
    }
    /// Reuse the complete financial-origin checks, but discard their private
    /// preparation object here. No projected writer plan escapes this owner.
    pub(super) fn validate_financial_origins(
        &self,
        history: &ReconciledAuthorityHistory,
    ) -> Result<()> {
        // The complete V2 audit was validated against ALL transport origins
        // during read(). Do not call the old construction-only validator on its
        // inner projection. This temporary object validates financial cells
        // only, is discarded here, and can never escape as an import plan.
        let union = self
            .local
            .offline
            .reconcile_transport_financial_branch(history, &self.complete)?;
        let _validated =
            PreparedWriterHistory::prepare_validated_branches(&self.local, history, union)?;
        Ok(())
    }
    pub(super) fn local(&self) -> &WriterLocalInventory {
        &self.local
    }
    pub(super) fn construction(
        &self,
    ) -> &wholepact_authority::construction_transport_handoff_v1::ConstructionHistoryWithTransportV1
    {
        &self.complete
    }
    pub(super) fn audit(&self) -> &CommonContextSignerAuditInventoryV2 {
        &self.audit
    }
}

#[derive(Serialize)]
pub(super) struct PreparedWriterHistory {
    // Preserve the original v1 vector order and representation when online-only.
    online: Vec<ReservationPermit>,
    offline: Vec<PreparedOfflineExposure>,
    local_commitment: String,
    retained_offline_review: Vec<OfflineWriterReviewOrigin>,
    retained_offline_enrollments: Vec<OfflineEnrollmentPolicy>,
    retained_offline_intents: Vec<wholepact_authority::offline::OfflineReservationIntent>,
    // Preserve the complete inert records and their selected input/obligation
    // exclusions. Skipping an empty field preserves legacy review digests.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    construction: Vec<(String, ManualRosterConstructionHistoryRecordV2)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    common_context_history: Option<wholepact_authority::ConstructionHistoryV2>,
    #[serde(skip_serializing_if = "Option::is_none")]
    common_context_audit: Option<CommonContextSignerAuditInventoryV1>,
}
#[derive(Serialize)]
struct OfflineWriterReviewOrigin {
    authorization_id: String,
    local_admission: Option<OfflineLocalAdmissionHistory>,
    original: Option<OfflineOriginalConsentHistory>,
    key_use: Option<OfflineLocalKeyUseHistory>,
    retained_result: Option<OfflineRetainedResultHistory>,
    signature_knowledge: &'static str,
}
#[derive(Serialize)]
struct PreparedOfflineExposure {
    admission: OfflineAuthorizationAdmission,
    policy: OfflineEnrollmentPolicy,
    provenance: OfflineRemoteHistoryProvenance,
}
impl PreparedWriterHistory {
    /// Sole production constructor: complete authenticated replay plus one
    /// transactionally validated local snapshot. It is not a write capability.
    pub(super) fn prepare(
        local: &WriterLocalInventory,
        history: &ReconciledAuthorityHistory,
    ) -> Result<Self> {
        let union = local.offline_history().reconcile_reservations(history)?;
        let complete_construction = history
            .construction_history_v2()
            .map_err(|_| JournalError::ConstructionHistoryUnsupported)?;
        local
            .common_context_audit
            .validate_against(&complete_construction)?;
        Self::prepare_validated_branches(local, history, union)
    }

    fn prepare_validated_branches(
        local: &WriterLocalInventory,
        history: &ReconciledAuthorityHistory,
        union: offline_reconciliation::OfflineReconciliationInventory<'_>,
    ) -> Result<Self> {
        let mut online = Vec::new();
        let mut offline = Vec::new();
        for entry in history.reservation_evidence() {
            match entry {
                ReservationEvidenceRef::BornOfflineV1(_) => {
                    return Err(JournalError::RecoveryRequired);
                }
                ReservationEvidenceRef::OnlineV2(permit) => online.push(permit.clone()),
                ReservationEvidenceRef::OfflineV1(admission) => {
                    let operation = history
                        .offline_enrollment_operation(
                            &admission.request.intent.terms.offline_policy_digest,
                        )
                        .map_err(|_| JournalError::Conflict)?
                        .ok_or(JournalError::InvalidBinding)?;
                    let OwnerControl::EnrollOfflinePolicy { policy, .. } = &operation.control
                    else {
                        return Err(JournalError::InvalidBinding);
                    };
                    let retained = union
                        .offline_origins()
                        .binary_search_by(|o| {
                            o.terms()
                                .authorization_id
                                .cmp(&admission.request.intent.terms.authorization_id)
                        })
                        .ok()
                        .and_then(|index| union.offline_origins()[index].retained_history());
                    let provenance =
                        if let Some(old) = retained.and_then(OfflineOriginHistory::provenance) {
                            // A later authenticated head must NOT rewrite immutable
                            // provenance from the first exact import.
                            if old.enrollment_operation != *operation
                                || old.account_policy != *history.account_policy()
                                || old.witness != *history.disclosure()
                                || !history.contains_head(&old.history_head)
                            {
                                return Err(JournalError::Conflict);
                            }
                            old.clone()
                        } else {
                            OfflineRemoteHistoryProvenance {
                                account_policy: history.account_policy().clone(),
                                enrollment_operation: operation.clone(),
                                witness: history.disclosure().clone(),
                                history_head: history.snapshot().head.clone(),
                                history_digest: history
                                    .history_digest()
                                    .map_err(|_| JournalError::InvalidBinding)?,
                            }
                        };
                    provenance.validate(admission, policy)?;
                    offline.push(PreparedOfflineExposure {
                        admission: admission.clone(),
                        policy: policy.clone(),
                        provenance,
                    });
                }
            }
        }
        if offline.is_empty()
            && union.construction_records().is_empty()
            && union.construction_history_v2().is_none()
            && history.snapshot().transport_fences.is_none()
        {
            // Do not infer that a sorted enum projection preserves legacy bytes.
            // Retain the original guarded accessor and exact vector ordering.
            online = history
                .permits()
                .map_err(|_| JournalError::OfflineHistoryUnsupported)?
                .to_vec();
        }
        let retained_offline_review = local
            .offline
            .admitted_origins()
            .iter()
            .map(|o| {
                let authorization_id = o
                    .local_admission()
                    .map(|a| a.terms.authorization_id.clone())
                    .or_else(|| {
                        o.admission()
                            .map(|a| a.request.intent.terms.authorization_id.clone())
                    })
                    .ok_or(JournalError::InvalidBinding)?;
                let signature_knowledge = match o.signature_knowledge() {
                    OfflineSignatureKnowledge::HistoricalAdmissionSignatureUnknown => {
                        "historical_admission_signature_unknown"
                    }
                    OfflineSignatureKnowledge::OriginalConsentRetainedSignatureUnknown => {
                        "original_consent_retained_signature_unknown"
                    }
                    OfflineSignatureKnowledge::LocalKeyUseStartedSignatureUnknown => {
                        "local_key_use_started_signature_unknown"
                    }
                    OfflineSignatureKnowledge::ExactResultRetainedCurrentValidityUnknown => {
                        "exact_result_retained_current_validity_unknown"
                    }
                };
                Ok(OfflineWriterReviewOrigin {
                    authorization_id,
                    local_admission: o.local_admission().cloned(),
                    original: o.original_consent().cloned(),
                    key_use: o.local_key_use().cloned(),
                    retained_result: o.retained_result().cloned(),
                    signature_knowledge,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let prepared = Self {
            online,
            offline,
            local_commitment: local.commitment().to_owned(),
            retained_offline_review,
            retained_offline_enrollments: local.offline.enrollments().to_vec(),
            retained_offline_intents: local.offline.reservation_intents().to_vec(),
            common_context_history: union.construction_history_v2().cloned(),
            common_context_audit: (!local.common_context_audit.rows.is_empty())
                .then(|| local.common_context_audit.clone()),
            construction: union
                .construction_records()
                .iter()
                .map(|(operation, record)| ((*operation).to_owned(), (*record).clone()))
                .collect(),
        };
        prepared.validate_origins(local)?;
        Ok(prepared)
    }
    /// Explicit source support boundary. Removing it requires coherent recovery,
    /// account-use, v2 host IPC, returned-result intake and current dispatch.
    pub(super) fn require_enabled(&self) -> Result<()> {
        self.require_financial_construction_supported()?;
        if !self.offline.is_empty() {
            return Err(JournalError::OfflineHistoryUnsupported);
        }
        Ok(())
    }
    fn require_financial_construction_supported(&self) -> Result<()> {
        if !self.construction.is_empty()
            || self.common_context_history.is_some()
            || self.common_context_audit.is_some()
        {
            return Err(JournalError::ConstructionHistoryUnsupported);
        }
        Ok(())
    }
    pub(super) fn legacy_online_permits(&self) -> Result<&[ReservationPermit]> {
        self.require_enabled()?;
        Ok(&self.online)
    }
    pub(super) fn len(&self) -> usize {
        self.online.len()
            + self.offline.len()
            + self
                .construction
                .iter()
                .filter(|(_, record)| {
                    matches!(
                        record,
                        ManualRosterConstructionHistoryRecordV2::Reservation { .. }
                    )
                })
                .count()
            + self
                .common_context_history
                .iter()
                .flat_map(|h| h.origins())
                .filter(|o| {
                    matches!(
                        o,
                        wholepact_authority::ConstructionOriginHistoryV2::CommonContextV3 { .. }
                    )
                })
                .count()
    }
    pub(super) fn has_offline(&self) -> bool {
        !self.offline.is_empty()
    }
    pub(super) fn require_unchanged_local(&self, local: &WriterLocalInventory) -> Result<()> {
        if local.commitment != self.local_commitment
            || self.common_context_audit.as_ref()
                != (!local.common_context_audit.rows.is_empty())
                    .then_some(&local.common_context_audit)
        {
            return Err(JournalError::Conflict);
        }
        self.validate_origins(local)
    }
    fn evidence(&self) -> impl Iterator<Item = ReservationEvidenceRef<'_>> {
        self.online
            .iter()
            .map(ReservationEvidenceRef::OnlineV2)
            .chain(
                self.offline
                    .iter()
                    .map(|o| ReservationEvidenceRef::OfflineV1(&o.admission)),
            )
    }
    fn validate_origins(&self, local: &WriterLocalInventory) -> Result<()> {
        let union = offline_reconciliation::join_replayed(&local.offline, self.evidence())?
            .with_construction_records(self.construction.iter().map(|(id, r)| (id.as_str(), r)))?
            .with_common_context_history(self.common_context_history.clone())?;
        union.require_retained_offline_coverage()?;
        let online: BTreeMap<_, _> = self
            .online
            .iter()
            .map(|p| (p.request.authorization_id.as_str(), p))
            .collect();
        let offline: BTreeSet<_> = self
            .offline
            .iter()
            .map(|p| p.admission.request.intent.terms.authorization_id.as_str())
            .collect();
        for retained in &local.remote_online {
            if online
                .get(retained.request.authorization_id.as_str())
                .copied()
                != Some(retained)
            {
                return Err(JournalError::Conflict);
            }
        }
        for original in &local.originals {
            let t = original.original_consent().terms();
            if offline.contains(t.authorization_id.as_str()) {
                return Err(JournalError::Conflict);
            }
            if let Some(remote) = online.get(t.authorization_id.as_str()) {
                validate_original_permit(original, remote)?;
            }
            // An unmatched online original remains in the exact local snapshot;
            // writer handoff does not delete it or confer a new native lifetime.
        }
        Ok(())
    }
    /// Only called from the actual approved writer transaction. Gate is checked
    /// again BEFORE the first insert, so even an internal mistaken caller cannot
    /// partially import an offline-bearing plan and then discover unavailability.
    pub(super) fn import_enabled(&self, tx: &Transaction<'_>, account: &str) -> Result<()> {
        self.require_enabled()?;
        offline_history::require_legacy_journal(tx)?;
        self.import_complete(tx, account)
    }
    /// Shared PRIVATE reconstruction kernel, not a live import capability.
    /// Writer and recovery callers must enforce their own explicit unavailable
    /// gate before external storage mutation and hold their real native/fence
    /// authority. This function never manufactures local consent or a result.
    pub(super) fn import_complete(&self, tx: &Transaction<'_>, account: &str) -> Result<()> {
        // This private financial reconstruction kernel has no construction
        // storage schema. Refuse before any financial row is written.
        self.require_financial_construction_supported()?;
        for permit in &self.online {
            authority::retain_remote_exposure(tx, permit, account)?;
        }
        for entry in &self.offline {
            retain_offline_exposure(tx, entry, account)?;
        }
        self.verify_imported_sets(tx, account)
    }
    fn verify_imported_sets(&self, c: &Connection, account: &str) -> Result<()> {
        let online: BTreeMap<_, _> = self
            .online
            .iter()
            .map(|p| (p.request.authorization_id.as_str(), p))
            .collect();
        let offline: BTreeMap<_, _> = self
            .offline
            .iter()
            .map(|p| {
                (
                    p.admission.request.intent.terms.authorization_id.as_str(),
                    &p.admission,
                )
            })
            .collect();
        if online.len() != self.online.len() || offline.len() != self.offline.len() {
            return Err(JournalError::Conflict);
        }
        let mut q = c.prepare("SELECT authorization_id,payload FROM signer_remote_exposures ORDER BY authorization_id")?;
        let actual = q
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if actual.len() != self.online.len() {
            return Err(JournalError::Conflict);
        }
        for (id, payload) in actual {
            let p: ReservationPermit = decode(payload)?;
            if p.request.authorization_id != id || online.get(id.as_str()).copied() != Some(&p) {
                return Err(JournalError::Conflict);
            }
        }
        let all = offline_history::read_all(c, account)?;
        if all.len() != self.offline.len() {
            return Err(JournalError::Conflict);
        }
        for origin in &all {
            // Every origin is visited; minimal-only evidence cannot disappear
            // from a successful remote-continuity comparison.
            let admission = origin.admission().ok_or(JournalError::RecoveryRequired)?;
            if offline
                .get(admission.request.intent.terms.authorization_id.as_str())
                .copied()
                != Some(admission)
            {
                return Err(JournalError::Conflict);
            }
        }
        Ok(())
    }
}

fn retain_offline_exposure(
    tx: &Transaction<'_>,
    entry: &PreparedOfflineExposure,
    account: &str,
) -> Result<()> {
    let a = &entry.admission;
    let p = &entry.policy;
    let t = &a.request.intent.terms;
    entry.provenance.validate(a, p)?;
    if t.account_id != account {
        return Err(JournalError::InvalidBinding);
    }
    let collision: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM signer_original_consents WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_remote_exposures WHERE authorization_id=?1)", [&t.authorization_id], |r| r.get(0))?;
    if collision {
        return Err(JournalError::Conflict);
    }
    let local: Option<String> = tx
        .query_row(
            "SELECT payload FROM signer_offline_local_admissions WHERE authorization_id=?1",
            [&t.authorization_id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(raw) = local {
        let local: OfflineLocalAdmissionHistory = decode(raw)?;
        local.validate_remote(a)?;
        if local.pinned_witness_certificate_digest != p.witness_certificate_digest {
            return Err(JournalError::Conflict);
        }
        validate_inputs(
            tx,
            "signer_offline_local_inputs",
            &t.authorization_id,
            account,
            t.inputs.iter().map(|i| i.nullifier.as_str()),
        )?;
    }
    let policy_digest = p
        .policy_digest()
        .map_err(|_| JournalError::InvalidBinding)?;
    let intent_digest = a
        .request
        .intent
        .intent_digest()
        .map_err(|_| JournalError::InvalidBinding)?;
    let policy_raw = encode(p)?;
    let old: Option<String> = tx
        .query_row(
            "SELECT payload FROM signer_offline_enrollments WHERE policy_digest=?1",
            [&policy_digest],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(old) = old {
        if old != *policy_raw {
            return Err(JournalError::Conflict);
        }
    } else {
        tx.execute(
            "INSERT INTO signer_offline_enrollments VALUES(?1,?2,?3,?4)",
            params![
                policy_digest,
                p.enrollment_ref,
                account,
                policy_raw.as_str()
            ],
        )?;
    }
    let intent_raw = encode(&a.request.intent)?;
    let old: Option<(String, String)> = tx
        .query_row(
            "SELECT intent_digest,payload FROM signer_offline_intents WHERE authorization_id=?1",
            [&t.authorization_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((key, old)) = old {
        if key != intent_digest || old != *intent_raw {
            return Err(JournalError::Conflict);
        }
    } else {
        tx.execute(
            "INSERT INTO signer_offline_intents VALUES(?1,?2,?3,?4)",
            params![
                intent_digest,
                t.authorization_id,
                policy_digest,
                intent_raw.as_str()
            ],
        )?;
    }
    let admission_raw = encode(a)?;
    let old: Option<String> = tx
        .query_row(
            "SELECT payload FROM signer_offline_admissions WHERE authorization_id=?1",
            [&t.authorization_id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(old) = old {
        if old != *admission_raw {
            return Err(JournalError::Conflict);
        }
    } else {
        tx.execute(
            "INSERT INTO signer_offline_admissions VALUES(?1,?2,?3)",
            params![t.authorization_id, a.request_digest, admission_raw.as_str()],
        )?;
    }
    let provenance_raw = encode(&entry.provenance)?;
    let old: Option<String> = tx
        .query_row(
            "SELECT payload FROM signer_offline_remote_exposures WHERE authorization_id=?1",
            [&t.authorization_id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(old) = old {
        if old != *provenance_raw {
            return Err(JournalError::Conflict);
        }
    } else {
        tx.execute(
            "INSERT INTO signer_offline_remote_exposures VALUES(?1,?2,?3,?4,?5)",
            params![
                t.authorization_id,
                account,
                t.obligation_id,
                t.maximum_debit_zatoshis.to_string(),
                provenance_raw.as_str()
            ],
        )?;
        for input in &t.inputs {
            tx.execute(
                "INSERT INTO signer_offline_remote_inputs VALUES(?1,?2,?3)",
                params![t.authorization_id, account, input.nullifier],
            )?;
        }
    }
    validate_inputs(
        tx,
        "signer_offline_remote_inputs",
        &t.authorization_id,
        account,
        t.inputs.iter().map(|i| i.nullifier.as_str()),
    )?;
    // The caller verifies the COMPLETE final typed inventory once after the
    // batch. Re-reading every row after every insert would be quadratic.
    Ok(())
}

pub(super) fn validate_original_permit(
    original: &OriginalAuthorizationEvidence,
    permit: &ReservationPermit,
) -> Result<()> {
    let consent = original.original_consent();
    let t = consent.terms();
    let (enrollment_ref, recipient_scope_digest) =
        durable_born_policy_v1::witness_policy_scope(original)?;
    let r = &permit.request;
    if consent.reference() != r.original_consent_ref
        || t.automation.as_ref().map(|a| &a.grant) != r.automation.as_ref()
        || t.authorization_id != r.authorization_id
        || t.authorization_id != r.operation_id
        || original
            .accepted_manifest()
            .proposal_input()
            .manifest
            .agreement
            .network_profile_id
            != r.network_profile_id
        || t.account_id != r.account_id
        || t.obligation_id != r.obligation_id
        || t.maximum_debit_zatoshis != r.maximum_debit_zatoshis
        || t.receipt.writer_epoch != r.writer_epoch
        || enrollment_ref != r.enrollment_ref
        || recipient_scope_digest != r.recipient_scope_digest
        || t.automation
            .as_ref()
            .map_or(t.receipt.expires_at_ms(), |a| a.authorization_expires_at_ms)
            != r.permit_expires_at_ms
        || t.accepted_manifest_ref != r.accepted_manifest_ref
        || t.agreement_id != r.agreement_id
        || t.proposal_id != r.proposal_id
        || t.proposal_digest != r.proposal_digest
        || t.manifest_digest != r.manifest_digest
        || t.effects_digest != r.effects_digest
        || t.artifact_digest != r.artifact_digest
        || t.review_binding != r.review_binding
        || t.fee_share_zatoshis != r.fee_share_zatoshis
        || t.transaction_fee_zatoshis != r.transaction_fee_zatoshis
        || t.transaction_expiry_height != r.transaction_expiry_height
        || t.receipt.reviewed_at_ms != r.reviewed_at_ms
        || t.input_bindings.len() != r.inputs.len()
        || t.input_bindings.iter().zip(&r.inputs).any(|(a, b)| {
            a.input_id != b.input_id
                || a.nullifier != b.nullifier
                || a.action_index != b.action_index
                || a.value_zatoshis != b.value_zatoshis
        })
    {
        return Err(JournalError::Conflict);
    }
    Ok(())
}

fn validate_inputs<'a>(
    c: &Connection,
    table: &str,
    authorization: &str,
    account: &str,
    nullifiers: impl Iterator<Item = &'a str>,
) -> Result<()> {
    // Only these executable-owned identifiers are accepted.
    let column = match table {
        "signer_remote_inputs" | "signer_offline_remote_inputs" | "signer_offline_local_inputs" => {
            "nullifier"
        }
        "signer_input_reservations" => "input_id",
        _ => return Err(JournalError::InvalidBinding),
    };
    let mut q = c.prepare(&format!(
        "SELECT account_id,{column} FROM {table} WHERE authorization_id=?1"
    ))?;
    let actual = q
        .query_map([authorization], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    let expected = nullifiers
        .map(|v| (account.to_string(), v.to_string()))
        .collect();
    if actual != expected {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}

/// Internal exact-change fence, NOT a backup/provenance/authentication claim.
/// Uses maintained SHA-256 with explicit table/column/typed-cell framing; no
/// secret or raw result leaves this function. All tables are included, including
/// v12 account-use tables; schema equality was checked before calling it.
pub(super) fn complete_journal_commitment(c: &Connection) -> Result<String> {
    use sha2::{Digest, Sha256};
    fn field(h: &mut Sha256, bytes: &[u8]) {
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
    }
    let mut h = Sha256::new();
    h.update(b"wholepact:writer-complete-journal-snapshot:v2\0");
    let mut q = c.prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")?;
    let tables = q
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for table in tables {
        field(&mut h, table.as_bytes());
        let quoted = table.replace('"', "\"\"");
        let mut q = c.prepare(&format!("SELECT * FROM \"{quoted}\""))?;
        let columns = q
            .column_names()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        drop(q);
        h.update((columns.len() as u64).to_be_bytes());
        for column in &columns {
            field(&mut h, column.as_bytes());
        }
        let ordering = (1..=columns.len())
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        q = c.prepare(&format!("SELECT * FROM \"{quoted}\" ORDER BY {ordering}"))?;
        let mut rows = q.query([])?;
        while let Some(row) = rows.next()? {
            h.update([1]);
            for i in 0..columns.len() {
                match row.get_ref(i)? {
                    ValueRef::Null => h.update([0]),
                    ValueRef::Integer(v) => {
                        h.update([1]);
                        h.update(v.to_be_bytes());
                    }
                    ValueRef::Text(v) => {
                        h.update([2]);
                        field(&mut h, v);
                    }
                    _ => return Err(JournalError::InvalidBinding),
                }
            }
        }
        h.update([0]);
    }
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
#[path = "writer_history_tests.rs"]
mod tests;

/// Archive-only complete local typed validation. No current witness or writer
/// owner is returned. Live restriction publication additionally requires the
/// full authenticated transport/financial replay through its dedicated reader.
#[cfg(all(feature = "pending-birth-owner-signing", target_os = "linux"))]
pub(super) fn validate_permanent_stop_archive_cells(
    c: &Connection,
    account: &SignerAccountState,
    limits: (u64, u64),
) -> Result<serde_json::Value> {
    let named = named_recipient_inventory::read_all(c, &account.account_id)?;
    let local = WriterLocalInventory::read_existing_origin_cells(c, account, limits)?;
    let audit = common_context_reentry_audit_v1::read_complete(c, &account.account_id)?;
    if audit.original != local.common_context_audit {
        return Err(JournalError::InvalidBinding);
    }
    offline_receipts::validate_all(c, &account.account_id)?;
    let online=local.originals.iter().map(|o|serde_json::json!({"terms":o.original_consent().terms(),"original_reference":o.original_consent().reference()})).collect::<Vec<_>>();
    let offline=local.offline.admitted_origins().iter().map(|o|serde_json::json!({"local_admission":o.local_admission(),"original_consent":o.original_consent(),"key_use":o.local_key_use(),"retained_result":o.retained_result(),"signature_knowledge":format!("{:?}",o.signature_knowledge())})).collect::<Vec<_>>();
    Ok(
        serde_json::json!({"all_local_original_online_consent_terms":online,"all_retained_remote_online_reservations":local.remote_online,"retained_legacy_offline_origins":offline,"named_recipient_history":named,"named_recipient_exposure":"UNKNOWN; every named original, Started marker and result remains retained. The existing financial projection does not account for named origins and cannot activate a writer.","offline_enrollments":local.offline.enrollments(),"offline_intents":local.offline.reservation_intents(),"complete_common_context_audit":audit,"complete_local_journal_commitment":local.commitment(),"remote_exposure":"UNKNOWN until independent complete authenticated witness replay; local absence is never emptiness or no-exposure evidence"}),
    )
}
