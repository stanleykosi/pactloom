//! Complete typed offline history in the actual encrypted consent journal.
//!
//! This module is a reader and preservation foundation, not an issuer. No
//! public/native write or continuation constructor is enabled. In particular,
//! imported witness history cannot create an original native spending decision,
//! a local key-use fence, a result, or an absence-of-signature assertion.
use super::*;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use wholepact_authority::{
    AccountPolicy, AuthorityHead, OwnerControl, OwnerControlRequest, WitnessDisclosureDescriptor,
    offline::{
        OfflineAuthorizationAdmission, OfflineAuthorizationTerms, OfflineEnrollmentPolicy,
        OfflineReservationIntent,
    },
};

/// Retained provenance only. Shape validation or deserialization authenticates
/// nothing; a future importer must obtain these from a complete authenticated
/// history and the exact owner operation, under the native reconciliation lease.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineRemoteHistoryProvenance {
    pub account_policy: AccountPolicy,
    pub enrollment_operation: OwnerControlRequest,
    pub witness: WitnessDisclosureDescriptor,
    pub history_head: AuthorityHead,
    pub history_digest: String,
}
impl OfflineRemoteHistoryProvenance {
    pub(crate) fn validate(
        &self,
        admission: &OfflineAuthorizationAdmission,
        policy: &OfflineEnrollmentPolicy,
    ) -> Result<()> {
        let t = &admission.request.intent.terms;
        self.account_policy
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        self.witness
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        hash(&self.history_digest)?;
        hash(&self.history_head.digest)?;
        id(&self.enrollment_operation.operation_id)?;
        hash(&self.enrollment_operation.expected_head.digest)?;
        admission
            .validate_reserved_policy_bounds(&self.account_policy, policy)
            .map_err(|_| JournalError::InvalidBinding)?;
        let enrolled = match &self.enrollment_operation.control {
            OwnerControl::EnrollOfflinePolicy { policy, .. } => policy,
            _ => return Err(JournalError::InvalidBinding),
        };
        if enrolled != policy
            || self.enrollment_operation.account_id != t.account_id
            || self.enrollment_operation.network_profile_id != t.network_profile_id
            || self.enrollment_operation.writer_epoch == 0
            || self.enrollment_operation.expected_head.sequence
                >= admission.request.expected_head.sequence
            || self.witness.account_id != t.account_id
            || self.witness.network_profile_id != t.network_profile_id
            || self.witness.witness_id != admission.witness_id
            || self.witness.policy_digest != admission.witness_policy_digest
            || self.witness.pinned_server_certificate_digest != policy.witness_certificate_digest
            || self.history_head.sequence < admission.committed_head.sequence
            || (self.history_head.sequence == admission.committed_head.sequence
                && self.history_head != admission.committed_head)
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

/// Exact schema snapshot of the transport minimal statement. This avoids a
/// signer -> transport -> signer-release dependency cycle. Integration must keep
/// its canonical encoding/domain golden equal to transport's version-one DTO.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineMinimalAdmissionHistoryStatement {
    pub schema_version: u16,
    pub witness_id: String,
    pub witness_transport_key_digest: String,
    pub witness_policy_digest: String,
    pub operation_id: String,
    pub authorization_id: String,
    pub request_digest: String,
    pub intent_digest: String,
    pub terms_digest: String,
    pub review_package_digest: String,
    /// The recipient cannot recompute this from the deliberately smaller payload.
    /// It is a pinned-witness assertion about the retained original descriptor.
    pub original_admission_digest: String,
    pub original_export_plan_digest: String,
    pub committed_head: AuthorityHead,
    pub reserved_at_ms: u64,
    pub admission_expires_at_ms: u64,
}
impl OfflineMinimalAdmissionHistoryStatement {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(JournalError::InvalidBinding);
        }
        for id in [&self.witness_id, &self.operation_id, &self.authorization_id] {
            super::id(id)?;
        }
        for h in [
            &self.witness_transport_key_digest,
            &self.witness_policy_digest,
            &self.request_digest,
            &self.intent_digest,
            &self.terms_digest,
            &self.review_package_digest,
            &self.original_admission_digest,
            &self.original_export_plan_digest,
            &self.committed_head.digest,
        ] {
            hash(h)?;
        }
        if self.committed_head.sequence == 0
            || self.committed_head.sequence > i64::MAX as u64
            || self.reserved_at_ms == 0
            || self.reserved_at_ms >= self.admission_expires_at_ms
            || self.admission_expires_at_ms > i64::MAX as u64
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    /// Digest of the complete *minimal* statement, distinct from the assertion
    /// naming the original witness-private admission descriptor.
    pub fn statement_digest(&self) -> Result<String> {
        self.validate()?;
        Ok(transport_history_digest(
            b"wholepact.offline-minimal-admission.v1\0",
            encode(self)?.as_bytes(),
        ))
    }
}

fn transport_history_digest(domain: &[u8], value: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    hex::encode(hasher.finalize())
}

/// Minimal retained admission projection. Shape validation cannot establish
/// witness authentication; only a future qualified intake may append it. Exact
/// terms are necessary for conservative accounting even before final consent.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineLocalAdmissionHistory {
    pub statement: OfflineMinimalAdmissionHistoryStatement,
    pub statement_digest: String,
    pub owner_setup_digest: String,
    pub pinned_witness_certificate_digest: String,
    pub source_envelope_digest: String,
    pub source_content_digest: String,
    pub terms: OfflineAuthorizationTerms,
    pub intent_digest: String,
    pub admission_request_digest: String,
    pub authenticated_package_digest: String,
}
impl OfflineLocalAdmissionHistory {
    pub(crate) fn validate(&self) -> Result<()> {
        self.terms
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        self.statement.validate()?;
        for h in [
            &self.intent_digest,
            &self.admission_request_digest,
            &self.authenticated_package_digest,
            &self.statement_digest,
            &self.owner_setup_digest,
            &self.pinned_witness_certificate_digest,
            &self.source_envelope_digest,
            &self.source_content_digest,
        ] {
            hash(h)?;
        }
        if self.statement_digest != self.statement.statement_digest()?
            || self.statement.authorization_id != self.terms.authorization_id
            || self.statement.intent_digest != self.intent_digest
            || self.statement.request_digest != self.admission_request_digest
            || self.statement.terms_digest
                != self
                    .terms
                    .terms_digest()
                    .map_err(|_| JournalError::InvalidBinding)?
            || self.statement.review_package_digest != self.terms.review_package_digest
            || self.authenticated_package_digest != self.terms.review_package_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    pub(crate) fn validate_remote(&self, admission: &OfflineAuthorizationAdmission) -> Result<()> {
        self.validate()?;
        if self.statement.witness_id != admission.witness_id
            || self.statement.witness_transport_key_digest != admission.witness_transport_key_digest
            || self.statement.witness_policy_digest != admission.witness_policy_digest
            || self.statement.operation_id != admission.request.operation_id
            || self.statement.committed_head != admission.committed_head
            || self.statement.reserved_at_ms != admission.reserved_at_ms
            || self.statement.admission_expires_at_ms != admission.request.admission_expires_at_ms
            || self.statement.original_admission_digest
                != transport_history_digest(
                    b"wholepact.offline-original-admission-assertion.v1\0",
                    encode(admission)?.as_bytes(),
                )
            || self.terms != admission.request.intent.terms
            || self.intent_digest
                != admission
                    .request
                    .intent
                    .intent_digest()
                    .map_err(|_| JournalError::InvalidBinding)?
            || self.admission_request_digest != admission.request_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

/// Offline local decision receipt. No remote writer session/epoch is invented
/// on the disconnected device, and parsing this receipt is never native approval.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineNativeConsentHistoryReceipt {
    pub native_session_id: String,
    pub trusted_launch_measurement: String,
    pub permission_generation: u64,
    pub nonce: String,
    pub reviewed_at_ms: u64,
    pub expires_at_ms: u64,
    pub intent_digest: String,
    pub admission_request_digest: String,
    pub authenticated_package_digest: String,
}
impl OfflineNativeConsentHistoryReceipt {
    fn validate(&self) -> Result<()> {
        for h in [
            &self.native_session_id,
            &self.trusted_launch_measurement,
            &self.nonce,
            &self.intent_digest,
            &self.admission_request_digest,
            &self.authenticated_package_digest,
        ] {
            hash(h)?;
        }
        if self.permission_generation == 0
            || self.reviewed_at_ms == 0
            || self.expires_at_ms <= self.reviewed_at_ms
            || self.expires_at_ms - self.reviewed_at_ms > 120_000
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

/// Historical native decision, never a live approval. The intent digest remains
/// a separate field and is never written into original_consent_ref.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineOriginalConsentHistory {
    pub reference: String,
    pub account_id: String,
    pub return_recipient_key_digest: String,
    pub authorization_id: String,
    pub admission_request_digest: String,
    pub intent_digest: String,
    pub terms_digest: String,
    pub authenticated_package_digest: String,
    pub native_review_digest: String,
    pub receipt: OfflineNativeConsentHistoryReceipt,
}
impl OfflineOriginalConsentHistory {
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub fn receipt(&self) -> &OfflineNativeConsentHistoryReceipt {
        &self.receipt
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.receipt.validate()?;
        id(&self.account_id)?;
        id(&self.authorization_id)?;
        hash(&self.return_recipient_key_digest)?;
        for h in [
            &self.reference,
            &self.admission_request_digest,
            &self.intent_digest,
            &self.terms_digest,
            &self.authenticated_package_digest,
            &self.native_review_digest,
        ] {
            hash(h)?;
        }
        if self.receipt.intent_digest != self.intent_digest
            || self.receipt.admission_request_digest != self.admission_request_digest
            || self.receipt.authenticated_package_digest != self.authenticated_package_digest
            || self.reference == self.intent_digest
            || self.reference
                != digest(
                    "wholepact:offline-original-consent-history:v1",
                    &(
                        &self.account_id,
                        &self.authorization_id,
                        &self.return_recipient_key_digest,
                        &self.admission_request_digest,
                        &self.intent_digest,
                        &self.terms_digest,
                        &self.authenticated_package_digest,
                        &self.native_review_digest,
                        &self.receipt,
                    ),
                )?
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    pub(crate) fn validate_admission(
        &self,
        admission: &OfflineAuthorizationAdmission,
    ) -> Result<()> {
        self.validate()?;
        let request = &admission.request;
        if self.account_id != request.intent.terms.account_id
            || self.authorization_id != request.intent.terms.authorization_id
            || self.return_recipient_key_digest != request.intent.terms.return_recipient_key_digest
            || self.admission_request_digest != admission.request_digest
            || self.intent_digest
                != request
                    .intent
                    .intent_digest()
                    .map_err(|_| JournalError::InvalidBinding)?
            || self.terms_digest
                != request
                    .intent
                    .terms
                    .terms_digest()
                    .map_err(|_| JournalError::InvalidBinding)?
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

/// Local durable uncertainty fence. Its presence says an invocation may have
/// happened; its absence in a restored copy never says one did not happen.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineLocalKeyUseHistory {
    pub authorization_id: String,
    pub original_consent_ref: String,
    pub admission_request_digest: String,
    pub authenticated_package_digest: String,
}
impl OfflineLocalKeyUseHistory {
    pub(crate) fn validate(&self, original: &OfflineOriginalConsentHistory) -> Result<()> {
        if self.authorization_id != original.authorization_id
            || self.original_consent_ref != original.reference
            || self.admission_request_digest != original.admission_request_digest
            || self.authenticated_package_digest != original.authenticated_package_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

/// Exact retained artifact metadata. The reader proves storage/link integrity,
/// not current validity, execution, or returned-transport authentication.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineRetainedResultHistory {
    pub authorization_id: String,
    pub original_consent_ref: String,
    pub admission_request_digest: String,
    pub authenticated_package_digest: String,
    pub signed_artifact_digest: String,
    pub return_recipient_key_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfflineSignatureKnowledge {
    HistoricalAdmissionSignatureUnknown,
    OriginalConsentRetainedSignatureUnknown,
    LocalKeyUseStartedSignatureUnknown,
    ExactResultRetainedCurrentValidityUnknown,
}

/// Owned audit evidence only. No conversion to OriginalAuthorizationLease,
/// AuthenticatedPermit, key-use admission, dispatch or export capability exists.
#[derive(Clone)]
pub struct OfflineOriginHistory {
    local_admission: Option<OfflineLocalAdmissionHistory>,
    enrollment: Option<OfflineEnrollmentPolicy>,
    admission: Option<OfflineAuthorizationAdmission>,
    provenance: Option<OfflineRemoteHistoryProvenance>,
    original: Option<OfflineOriginalConsentHistory>,
    key_use: Option<OfflineLocalKeyUseHistory>,
    result: Option<(OfflineRetainedResultHistory, Zeroizing<String>)>,
}
impl OfflineOriginHistory {
    pub fn local_admission(&self) -> Option<&OfflineLocalAdmissionHistory> {
        self.local_admission.as_ref()
    }
    pub fn enrollment(&self) -> Option<&OfflineEnrollmentPolicy> {
        self.enrollment.as_ref()
    }
    pub fn admission(&self) -> Option<&OfflineAuthorizationAdmission> {
        self.admission.as_ref()
    }
    pub fn provenance(&self) -> Option<&OfflineRemoteHistoryProvenance> {
        self.provenance.as_ref()
    }
    pub fn original_consent(&self) -> Option<&OfflineOriginalConsentHistory> {
        self.original.as_ref()
    }
    pub fn local_key_use(&self) -> Option<&OfflineLocalKeyUseHistory> {
        self.key_use.as_ref()
    }
    /// Metadata only. A history read lease never grants raw signature export.
    /// Exact retained bytes remain private for integrity/backup preservation;
    /// future export requires a separate live native disclosure capability.
    pub fn retained_result(&self) -> Option<&OfflineRetainedResultHistory> {
        self.result.as_ref().map(|(record, _)| record)
    }
    pub fn signature_knowledge(&self) -> OfflineSignatureKnowledge {
        if self.result.is_some() {
            OfflineSignatureKnowledge::ExactResultRetainedCurrentValidityUnknown
        } else if self.key_use.is_some() {
            OfflineSignatureKnowledge::LocalKeyUseStartedSignatureUnknown
        } else if self.original.is_some() {
            OfflineSignatureKnowledge::OriginalConsentRetainedSignatureUnknown
        } else {
            OfflineSignatureKnowledge::HistoricalAdmissionSignatureUnknown
        }
    }
}
/// Includes nonbinding prereview history as well as every admitted origin.
/// Nothing is silently dropped when there is no admission or final consent.
pub struct OfflineHistoryInventory {
    enrollments: Vec<OfflineEnrollmentPolicy>,
    reservation_intents: Vec<OfflineReservationIntent>,
    admitted_origins: Vec<OfflineOriginHistory>,
}
impl OfflineHistoryInventory {
    pub fn enrollments(&self) -> &[OfflineEnrollmentPolicy] {
        &self.enrollments
    }
    pub fn reservation_intents(&self) -> &[OfflineReservationIntent] {
        &self.reservation_intents
    }
    pub fn admitted_origins(&self) -> &[OfflineOriginHistory] {
        &self.admitted_origins
    }
}

impl SignerConsentJournal {
    /// Inspect complete retained offline origin under a current read lease. The
    /// result is historical even when a local original or result survived.
    pub fn offline_history_inventory(
        &self,
        session: &SignerConsentSession,
    ) -> Result<OfflineHistoryInventory> {
        let account = self.account_state()?;
        let lease = session.read_lease(&self.binding(), &account)?;
        let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        storage::check_account(&tx, &account)?;
        storage::bounded(&tx, self.capacity_limits())?;
        let inventory = read_inventory(&tx, &account.account_id)?;
        lease.check_current()?;
        tx.rollback()?;
        Ok(inventory)
    }
}

/// Caller must retain a single read/write transaction for the complete inventory.
pub(super) fn read_inventory(c: &Connection, account: &str) -> Result<OfflineHistoryInventory> {
    named_recipient_inventory::require_absent(c)?;
    read_existing_origin_cells(c, account)
}
/// Private branch for the restriction-only complete archive renderer. The
/// caller must retain separate named history; this is not a complete financial
/// inventory and never enables ordinary reconciliation or recovery.
pub(super) fn read_existing_origin_cells(
    c: &Connection,
    account: &str,
) -> Result<OfflineHistoryInventory> {
    if c.is_autocommit() {
        return Err(JournalError::InvalidBinding);
    }
    let admitted_origins = read_all(c, account)?;
    let mut q =
        c.prepare("SELECT payload FROM signer_offline_enrollments ORDER BY policy_digest")?;
    let enrollments = q
        .query_map([], |r| r.get::<_, String>(0))?
        .map(|row| decode(row?))
        .collect::<Result<Vec<OfflineEnrollmentPolicy>>>()?;
    drop(q);
    let mut q = c.prepare("SELECT payload FROM signer_offline_intents ORDER BY intent_digest")?;
    let reservation_intents = q
        .query_map([], |r| r.get::<_, String>(0))?
        .map(|row| decode(row?))
        .collect::<Result<Vec<OfflineReservationIntent>>>()?;
    Ok(OfflineHistoryInventory {
        enrollments,
        reservation_intents,
        admitted_origins,
    })
}

/// Validate every row, including prereview records without an admission and all
/// denormalized columns. This is called at open/export/recovery validation.
pub(super) fn read_all(c: &Connection, account: &str) -> Result<Vec<OfflineOriginHistory>> {
    let mut policies = BTreeMap::new();
    let mut q = c.prepare(
        "SELECT policy_digest,enrollment_ref,account_id,payload FROM signer_offline_enrollments",
    )?;
    let rows = q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;
    for row in rows {
        let (key, enrollment, row_account, raw) = row?;
        let policy: OfflineEnrollmentPolicy = decode(raw)?;
        policy
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        if policy
            .policy_digest()
            .map_err(|_| JournalError::InvalidBinding)?
            != key
            || policy.enrollment_ref != enrollment
            || policy.account_id != account
            || row_account != account
        {
            return Err(JournalError::InvalidBinding);
        }
        policies.insert(key, policy);
    }
    drop(q);
    let mut intents = BTreeMap::new();
    let mut q = c.prepare(
        "SELECT intent_digest,authorization_id,policy_digest,payload FROM signer_offline_intents",
    )?;
    let rows = q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;
    for row in rows {
        let (key, authorization, policy_key, raw) = row?;
        let intent: OfflineReservationIntent = decode(raw)?;
        intent
            .validate()
            .map_err(|_| JournalError::InvalidBinding)?;
        let policy = policies
            .get(&policy_key)
            .ok_or(JournalError::InvalidBinding)?;
        if intent
            .intent_digest()
            .map_err(|_| JournalError::InvalidBinding)?
            != key
            || intent.terms.authorization_id != authorization
            || intent.terms.account_id != account
            || intent.terms.offline_policy_digest != policy_key
            || intent.terms.enrollment_ref != policy.enrollment_ref
            || intent.terms.offline_signer_key_digest != policy.offline_signer_key_digest
            || intent.terms.return_recipient_key_digest != policy.return_recipient_key_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        intents.insert(authorization, intent);
    }
    drop(q);
    let mut admissions = BTreeMap::new();
    let mut q =
        c.prepare("SELECT authorization_id,request_digest,payload FROM signer_offline_admissions")?;
    let rows = q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (authorization, request_digest, raw) = row?;
        let admission: OfflineAuthorizationAdmission = decode(raw)?;
        admission
            .matches_request(&admission.request)
            .map_err(|_| JournalError::InvalidBinding)?;
        if admission.request.intent.terms.authorization_id != authorization
            || admission.request_digest != request_digest
            || intents.get(&authorization) != Some(&admission.request.intent)
        {
            return Err(JournalError::InvalidBinding);
        }
        admissions.insert(authorization, admission);
    }
    drop(q);
    let mut local_admissions = read_local_admissions(c, account)?;
    let mut output = Vec::new();
    let mut q = c.prepare("SELECT authorization_id,account_id,obligation_id,maximum_debit,payload FROM signer_offline_remote_exposures ORDER BY authorization_id")?;
    let rows = q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    for row in rows {
        let (authorization, row_account, obligation, debit, raw) = row?;
        let admission = admissions
            .remove(&authorization)
            .ok_or(JournalError::InvalidBinding)?;
        let terms = &admission.request.intent.terms;
        if row_account != account
            || terms.account_id != account
            || terms.obligation_id != obligation
            || terms.maximum_debit_zatoshis.to_string() != debit
        {
            return Err(JournalError::InvalidBinding);
        }
        let policy = policies
            .get(&terms.offline_policy_digest)
            .ok_or(JournalError::InvalidBinding)?;
        let provenance: OfflineRemoteHistoryProvenance = decode(raw)?;
        provenance.validate(&admission, policy)?;
        let collision: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM signer_original_consents WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_remote_exposures WHERE authorization_id=?1)", [&authorization], |r| r.get(0))?;
        if collision {
            return Err(JournalError::Conflict);
        }
        validate_inputs(
            c,
            "signer_offline_remote_inputs",
            &authorization,
            account,
            terms,
        )?;
        let local_admission = local_admissions.remove(&authorization);
        if let Some(local) = &local_admission {
            local.validate_remote(&admission)?;
            if local.pinned_witness_certificate_digest != policy.witness_certificate_digest {
                return Err(JournalError::InvalidBinding);
            }
        }
        let original = read_original(
            c,
            &authorization,
            account,
            Some(&admission),
            local_admission.as_ref(),
        )?;
        let key_use = read_key_use(c, &authorization, original.as_ref())?;
        let result = read_result(c, &authorization, original.as_ref(), key_use.as_ref())?;
        output.push(OfflineOriginHistory {
            local_admission,
            enrollment: Some(policy.clone()),
            admission: Some(admission),
            provenance: Some(provenance),
            original,
            key_use,
            result,
        });
    }
    if !admissions.is_empty() {
        return Err(JournalError::InvalidBinding);
    }
    drop(q);
    // A disconnected device retains only its minimally disclosed original.
    // Do not demand a full witness descriptor, which includes unrelated totals
    // and writer/session metadata absent from the authenticated review package.
    for (authorization, local_admission) in local_admissions {
        let original = read_original(c, &authorization, account, None, Some(&local_admission))?;
        let collision: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM signer_original_consents WHERE authorization_id=?1 UNION ALL SELECT 1 FROM signer_remote_exposures WHERE authorization_id=?1)", [&authorization], |r| r.get(0))?;
        if collision {
            return Err(JournalError::Conflict);
        }
        let key_use = read_key_use(c, &authorization, original.as_ref())?;
        let result = read_result(c, &authorization, original.as_ref(), key_use.as_ref())?;
        output.push(OfflineOriginHistory {
            local_admission: Some(local_admission),
            enrollment: None,
            admission: None,
            provenance: None,
            original,
            key_use,
            result,
        });
    }
    let violations: u64 =
        c.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
            r.get(0)
        })?;
    if violations != 0 {
        return Err(JournalError::InvalidBinding);
    }
    Ok(output)
}
fn read_local_admissions(
    c: &Connection,
    account: &str,
) -> Result<BTreeMap<String, OfflineLocalAdmissionHistory>> {
    let mut q = c.prepare("SELECT authorization_id,account_id,obligation_id,maximum_debit,payload FROM signer_offline_local_admissions")?;
    let rows = q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    let mut output = BTreeMap::new();
    for row in rows {
        let (authorization, row_account, obligation, debit, payload) = row?;
        let local: OfflineLocalAdmissionHistory = decode(payload)?;
        local.validate()?;
        if local.terms.authorization_id != authorization
            || local.terms.account_id != account
            || row_account != account
            || local.terms.obligation_id != obligation
            || local.terms.maximum_debit_zatoshis.to_string() != debit
        {
            return Err(JournalError::InvalidBinding);
        }
        validate_inputs(
            c,
            "signer_offline_local_inputs",
            &authorization,
            account,
            &local.terms,
        )?;
        output.insert(authorization, local);
    }
    Ok(output)
}
fn validate_inputs(
    c: &Connection,
    table: &str,
    authorization: &str,
    account: &str,
    terms: &OfflineAuthorizationTerms,
) -> Result<()> {
    let mut q = c.prepare(&format!(
        "SELECT account_id,nullifier FROM {table} WHERE authorization_id=?1"
    ))?;
    let actual = q
        .query_map([authorization], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    let expected = terms
        .inputs
        .iter()
        .map(|i| (account.to_owned(), i.nullifier.clone()))
        .collect();
    if actual != expected {
        return Err(JournalError::InvalidBinding);
    }
    Ok(())
}
fn read_original(
    c: &Connection,
    authorization: &str,
    account: &str,
    admission: Option<&OfflineAuthorizationAdmission>,
    local_admission: Option<&OfflineLocalAdmissionHistory>,
) -> Result<Option<OfflineOriginalConsentHistory>> {
    let raw: Option<(String,String,String,String)> = c.query_row("SELECT reference,nonce,payload,account_id FROM signer_offline_original_consents WHERE authorization_id=?1",[authorization], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    raw.map(|(reference, nonce, payload, row_account)| {
        let original: OfflineOriginalConsentHistory = decode(payload)?;
        original.validate()?;
        if let Some(admission) = admission {
            original.validate_admission(admission)?;
        }
        let local = local_admission.ok_or(JournalError::InvalidBinding)?;
        if original.authorization_id != local.terms.authorization_id
            || original.return_recipient_key_digest != local.terms.return_recipient_key_digest
            || original.admission_request_digest != local.admission_request_digest
            || original.intent_digest != local.intent_digest
            || original.terms_digest
                != local
                    .terms
                    .terms_digest()
                    .map_err(|_| JournalError::InvalidBinding)?
            || original.authenticated_package_digest != local.authenticated_package_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        if original.account_id != account || row_account != account {
            return Err(JournalError::InvalidBinding);
        }
        if original.reference != reference
            || original.receipt.nonce != nonce
            || original.authorization_id != authorization
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(original)
    })
    .transpose()
}
fn read_key_use(
    c: &Connection,
    authorization: &str,
    original: Option<&OfflineOriginalConsentHistory>,
) -> Result<Option<OfflineLocalKeyUseHistory>> {
    let raw: Option<(String,String)> = c.query_row("SELECT original_consent_ref,payload FROM signer_offline_keyuse WHERE authorization_id=?1",[authorization], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
    raw.map(|(reference, payload)| {
        let record: OfflineLocalKeyUseHistory = decode(payload)?;
        record.validate(original.ok_or(JournalError::InvalidBinding)?)?;
        if record.authorization_id != authorization || record.original_consent_ref != reference {
            return Err(JournalError::InvalidBinding);
        }
        Ok(record)
    })
    .transpose()
}
fn read_result(
    c: &Connection,
    authorization: &str,
    original: Option<&OfflineOriginalConsentHistory>,
    key_use: Option<&OfflineLocalKeyUseHistory>,
) -> Result<Option<(OfflineRetainedResultHistory, Zeroizing<String>)>> {
    let raw: Option<(String,String,String)> = c.query_row("SELECT result_digest,result_hex,payload FROM signer_offline_results WHERE authorization_id=?1",[authorization], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    raw.map(|(saved_digest, raw_bytes, payload)| {
        use sha2::{Digest, Sha256};
        let bytes = Zeroizing::new(raw_bytes);
        if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
            return Err(JournalError::Limit);
        }
        let decoded =
            Zeroizing::new(hex::decode(bytes.as_str()).map_err(|_| JournalError::InvalidBinding)?);
        let record: OfflineRetainedResultHistory = decode(payload)?;
        let original = original.ok_or(JournalError::InvalidBinding)?;
        key_use
            .ok_or(JournalError::InvalidBinding)?
            .validate(original)?;
        if hex::encode(decoded.as_slice()) != *bytes
            || hex::encode(Sha256::digest(decoded.as_slice())) != saved_digest
            || record.signed_artifact_digest != saved_digest
            || record.authorization_id != authorization
            || record.original_consent_ref != original.reference
            || record.admission_request_digest != original.admission_request_digest
            || record.authenticated_package_digest != original.authenticated_package_digest
            || record.return_recipient_key_digest != original.return_recipient_key_digest
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok((record, bytes))
    })
    .transpose()
}

/// A local-only offline original cannot supply accountwide remote continuity.
/// Keep ordinary online issuance blocked until complete origin is reconciled.
pub(super) fn require_accountwide_online_admission(c: &Connection) -> Result<()> {
    named_recipient_inventory::require_absent(c)?;
    let missing: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM signer_offline_local_admissions o WHERE NOT EXISTS(SELECT 1 FROM signer_offline_remote_exposures r WHERE r.authorization_id=o.authorization_id))", [], |r| r.get(0))?;
    if missing {
        return Err(JournalError::OfflineHistoryUnsupported);
    }
    Ok(())
}

/// Legacy inventories are complete only for online origins. A local offline
/// row must not disappear merely because the remote history is still online-only.
pub(super) fn require_legacy_journal(c: &Connection) -> Result<()> {
    named_recipient_inventory::require_absent(c)?;
    let common: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM signer_common_context_audit_v3 UNION ALL SELECT 1 FROM signer_common_context_reentry_v1)",
        [],
        |r| r.get(0),
    )?;
    if common {
        return Err(JournalError::ConstructionHistoryUnsupported);
    }
    super::offline_receipts::require_legacy_journal(c)?;
    let any: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM signer_offline_enrollments UNION ALL SELECT 1 FROM signer_offline_intents UNION ALL SELECT 1 FROM signer_offline_admissions UNION ALL SELECT 1 FROM signer_offline_remote_exposures UNION ALL SELECT 1 FROM signer_offline_remote_inputs UNION ALL SELECT 1 FROM signer_offline_local_admissions UNION ALL SELECT 1 FROM signer_offline_local_inputs UNION ALL SELECT 1 FROM signer_offline_original_consents UNION ALL SELECT 1 FROM signer_offline_keyuse UNION ALL SELECT 1 FROM signer_offline_results)", [], |r| r.get(0))?;
    if any {
        return Err(JournalError::OfflineHistoryUnsupported);
    }
    Ok(())
}

/// Until every live reconciliation and recovery consumer has migrated, no
/// offline-bearing source can be activated by legacy online-only recovery.
#[cfg(all(
    feature = "native-ui",
    feature = "authority-signing",
    target_os = "linux"
))]
pub(super) fn require_legacy_recovery_source(
    source: &wholepact_storage_security::bundle::recovery::VerifiedSignerRecoverySource,
) -> Result<()> {
    if source.tables().iter().any(|t| {
        (t.name().starts_with("signer_named_recipient_")
            || t.name() == "signer_named_intent_outbox")
            && !t.rows().is_empty()
    }) {
        return Err(JournalError::NamedRecipientHistoryUnsupported);
    }
    if source.tables().iter().any(|t| {
        matches!(
            t.name(),
            "signer_common_context_audit_v3"
                | "signer_common_context_reentry_v1"
                | "signer_durable_construction_outbox"
        ) && !t.rows().is_empty()
    }) {
        return Err(JournalError::ConstructionHistoryUnsupported);
    }
    // Includes signer_offline_review_* receipt rows from v13. Older sealed
    // schema inventories may omit those tables; any present nonempty offline
    // table remains a hard refusal, never a filtered legacy inventory.
    if source
        .tables()
        .iter()
        .any(|t| t.name().starts_with("signer_offline_") && !t.rows().is_empty())
    {
        return Err(JournalError::OfflineHistoryUnsupported);
    }
    Ok(())
}

#[cfg(test)]
#[path = "offline_history_tests.rs"]
pub(super) mod tests;
