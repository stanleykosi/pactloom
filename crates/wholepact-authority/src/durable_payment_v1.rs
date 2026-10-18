//! Inert, exact durable-payment evidence. No value in this module is a native
//! approval, a verified PCZT, a writer capability, or permission to append.
//!
//! Native admission cannot be issued by the default public API:
//! ```compile_fail
//! use wholepact_authority::durable_payment_owner_v1::NativeDurablePaymentAdmissionSourceV1;
//! ```
use crate::{manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2, *};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use wholepact_core::manual_enrollment::ManualAccountIdentity;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableFixedCandidateBindingV1 {
    pub schema_version: u32,
    pub network_profile_id: String,
    pub agreement_id: String,
    pub obligation_id: String,
    pub proposal_id: String,
    pub revision: u32,
    pub expiry_height: u32,
    pub proposal_digest: String,
    pub manifest_digest: String,
    pub unsigned_artifact_digest: String,
    pub proved_artifact_digest: String,
    pub effects_commitment: String,
    pub policy_digest: String,
    pub review_binding: String,
    pub action_mapping_digest: String,
    pub anchor: String,
    pub proposal_binding: String,
}
impl DurableFixedCandidateBindingV1 {
    /// Byte-for-byte FixedProposalIdentityV1 canonical projection, not a proof.
    fn canonical_binding(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"wholepact:durable-fixed-proposal:pczt-0.10.0-pre.1:v1\0");
        h.update(self.schema_version.to_le_bytes());
        h.update(self.revision.to_le_bytes());
        h.update(self.expiry_height.to_le_bytes());
        for value in [
            &self.network_profile_id,
            &self.agreement_id,
            &self.obligation_id,
            &self.proposal_id,
            &self.proposal_digest,
            &self.manifest_digest,
            &self.unsigned_artifact_digest,
            &self.proved_artifact_digest,
            &self.effects_commitment,
            &self.policy_digest,
            &self.review_binding,
            &self.action_mapping_digest,
            &self.anchor,
        ] {
            h.update((value.len() as u64).to_le_bytes());
            h.update(value.as_bytes());
        }
        hex::encode(h.finalize())
    }
    pub fn validate(&self) -> Result<()> {
        for v in [
            &self.network_profile_id,
            &self.agreement_id,
            &self.obligation_id,
            &self.proposal_id,
        ] {
            id(v)?;
        }
        for v in [
            &self.proposal_digest,
            &self.manifest_digest,
            &self.unsigned_artifact_digest,
            &self.proved_artifact_digest,
            &self.effects_commitment,
            &self.policy_digest,
            &self.review_binding,
            &self.action_mapping_digest,
            &self.anchor,
            &self.proposal_binding,
        ] {
            hash(v)?;
        }
        if self.schema_version != 1
            || self.expiry_height == 0
            || self.proposal_binding != self.canonical_binding()
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurablePaymentAdmissionTermsV1 {
    pub version: u16,
    pub identity: ManualAccountIdentity,
    pub original_policy_digest: String,
    pub original_genesis_digest: String,
    pub original_birth_commit_digest: String,
    pub original_roster_extension_digest: String,
    pub original_enrollment_ref: String,
    pub writer_certificate_digest: String,
    pub fixed: DurableFixedCandidateBindingV1,
    pub authorization_id: String,
    pub recipient_policy_scope_digest: String,
    pub concrete_recipient_scope_digest: String,
    pub inputs: Vec<InputReservation>,
    pub maximum_debit_zatoshis: u64,
    pub fee_share_zatoshis: u64,
    pub transaction_fee_zatoshis: u64,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
}
impl DurablePaymentAdmissionTermsV1 {
    pub(crate) fn canonical_authorization_id(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"wholepact:durable-manual-proposal-authorization:v1\0");
        for value in [&self.fixed.proposal_binding, &self.identity.account_id] {
            h.update((value.len() as u64).to_le_bytes());
            h.update(value.as_bytes());
        }
        format!("durable-v1-{}", hex::encode(h.finalize()))
    }
    pub fn validate(&self) -> Result<()> {
        self.fixed.validate()?;
        hash(&self.identity.account_id)?;
        hash(&self.identity.full_viewing_key_digest)?;
        id(&self.identity.network_profile_id)?;
        if self.identity.derivation_domain.is_empty()
            || self.identity.derivation_domain.len() > 256
            || self
                .identity
                .derivation_domain
                .chars()
                .any(char::is_control)
        {
            return Err(AuthorityError::InvalidBinding);
        }
        id(&self.authorization_id)?;
        for v in [
            &self.original_policy_digest,
            &self.original_genesis_digest,
            &self.original_birth_commit_digest,
            &self.original_roster_extension_digest,
            &self.original_enrollment_ref,
            &self.writer_certificate_digest,
            &self.recipient_policy_scope_digest,
            &self.concrete_recipient_scope_digest,
        ] {
            hash(v)?;
        }
        if self.authorization_id != self.canonical_authorization_id()
            || self.version != 1
            || self.identity.network_profile_id != self.fixed.network_profile_id
            || self.valid_from_ms == 0
            || self.valid_until_ms <= self.valid_from_ms
            || self.valid_until_ms > i64::MAX as u64
            || self.inputs.is_empty()
            || self.inputs.len() > 256
            || self.maximum_debit_zatoshis == 0
            || self.maximum_debit_zatoshis > MAX_MONEY
            || self.fee_share_zatoshis > self.maximum_debit_zatoshis
            || self.fee_share_zatoshis > self.transaction_fee_zatoshis
            || self.transaction_fee_zatoshis > MAX_MONEY
        {
            return Err(AuthorityError::InvalidBinding);
        }
        let (mut ids, mut nfs, mut actions) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        let mut total = 0_u64;
        for i in &self.inputs {
            id(&i.input_id)?;
            hash(&i.nullifier)?;
            if i.action_index > 255
                || i.value_zatoshis == 0
                || i.value_zatoshis > MAX_MONEY
                || !ids.insert(&i.input_id)
                || !nfs.insert(&i.nullifier)
                || !actions.insert(i.action_index)
            {
                return Err(AuthorityError::InvalidBinding);
            }
            total = total
                .checked_add(i.value_zatoshis)
                .ok_or(AuthorityError::InvalidBinding)?;
        }
        if total > MAX_MONEY || total < self.maximum_debit_zatoshis {
            return Err(AuthorityError::InvalidBinding);
        }
        encode(self)?;
        Ok(())
    }
    pub(crate) fn validate_original(
        &self,
        p: &AccountPolicy,
        e: &ManualRosterEnrollmentExtensionV2,
    ) -> Result<()> {
        self.validate()?;
        e.validate_original_policy(p)?;
        let old = &e.account_extension;
        let s = &old.terms.scope;
        if self.identity != old.terms.identity
            || self.original_policy_digest != p.policy_digest()?
            || self.original_genesis_digest != old.terms.account_use_genesis_digest
            || self.original_birth_commit_digest != old.terms.birth_commit_digest
            || self.original_roster_extension_digest != e.digest()?
            || self.original_enrollment_ref != old.enrollment_ref
            || p.enrollment_refs.contains(&self.original_enrollment_ref)
            || self.writer_certificate_digest != p.initial_writer_certificate_digest
            || self.writer_certificate_digest != old.terms.signer.writer_certificate_digest
            || self.fixed.agreement_id != s.agreement_id
            || self.fixed.obligation_id != s.obligation_id
            || !p
                .recipient_scope_digests
                .contains(&self.recipient_policy_scope_digest)
            || !s
                .recipient_scope_digests
                .contains(&self.recipient_policy_scope_digest)
            || self.maximum_debit_zatoshis > s.per_operation_limit_zatoshis
            || self.maximum_debit_zatoshis > s.aggregate_budget_zatoshis
            || self.fee_share_zatoshis > s.maximum_fee_share_zatoshis
            || self.transaction_fee_zatoshis > s.maximum_transaction_fee_zatoshis
            || self.valid_from_ms < old.terms.issued_at_ms
            || self.valid_until_ms > s.expires_at_ms
            || self.valid_until_ms > p.policy_expires_at_ms
        {
            return Err(AuthorityError::PolicyDenied);
        }
        Ok(())
    }
    pub(crate) fn require_live(&self, now: u64) -> Result<()> {
        if now < self.valid_from_ms || now >= self.valid_until_ms {
            Err(AuthorityError::Expired)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurablePaymentAdmissionRecordV1 {
    pub terms: DurablePaymentAdmissionTermsV1,
    pub witness_native_review_digest: String,
}
fn request_terms(r: &OwnerControlRequest) -> Result<&DurablePaymentAdmissionTermsV1> {
    match &r.control {
        OwnerControl::AdmitDurablePaymentV1 { record } => Ok(&record.terms),
        _ => Err(AuthorityError::Permission),
    }
}
fn owner_operation_id(r: &OwnerControlRequest) -> Result<String> {
    Ok(format!(
        "durable-payment-admit-v1-{}",
        digest(
            "wholepact:durable-payment-owner-operation:v1",
            &(
                request_terms(r)?,
                &r.account_id,
                &r.network_profile_id,
                r.writer_epoch,
                &r.expected_head
            )
        )?
    ))
}
pub(crate) fn request_native_review_digest_v1(
    r: &OwnerControlRequest,
    disclosure: &WitnessDisclosureDescriptor,
) -> Result<String> {
    disclosure.validate()?;
    digest(
        "wholepact:durable-payment-witness-native-review:v1",
        &(
            request_terms(r)?,
            &r.account_id,
            &r.network_profile_id,
            r.writer_epoch,
            &r.expected_head,
            disclosure,
        ),
    )
}
impl DurablePaymentAdmissionRecordV1 {
    pub fn validate(&self) -> Result<()> {
        self.terms.validate()?;
        hash(&self.witness_native_review_digest)
    }
    pub(crate) fn validate_request_shape(&self, r: &OwnerControlRequest) -> Result<()> {
        self.validate()?;
        hash(&r.expected_head.digest)?;
        if !matches!(&r.control, OwnerControl::AdmitDurablePaymentV1 { record } if record.as_ref() == self)
            || request_terms(r)? != &self.terms
            || r.operation_id != owner_operation_id(r)?
            || r.account_id != self.terms.identity.account_id
            || r.network_profile_id != self.terms.identity.network_profile_id
            || r.writer_epoch == 0
            || r.writer_epoch > i64::MAX as u64
            || r.expected_head.sequence >= MAX_EVENTS
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    /// Validates inert request shape and digest correlation only. This does not
    /// issue native approval, current-source permission, or admission authority.
    pub fn validate_request(
        &self,
        r: &OwnerControlRequest,
        disclosure: &WitnessDisclosureDescriptor,
    ) -> Result<()> {
        self.validate_request_shape(r)?;
        if self.witness_native_review_digest != request_native_review_digest_v1(r, disclosure)?
            || disclosure.account_id != r.account_id
            || disclosure.network_profile_id != r.network_profile_id
            || disclosure.policy_digest != self.terms.original_policy_digest
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
    pub fn acquire_operation_id(&self, admission: &OwnerControlRequest) -> Result<String> {
        self.validate_request_shape(admission)?;
        Ok(format!(
            "durable-payment-acquire-v1-{}",
            digest("wholepact:durable-payment-acquire:v1", admission)?
        ))
    }
}
/// Inert builder from the same authenticated full history, never a native issuer.
pub fn prepare_durable_payment_request_v1(
    terms: DurablePaymentAdmissionTermsV1,
    history: &ReconciledAuthorityHistory,
) -> Result<OwnerControlRequest> {
    history.require_original_roster_preconstruction_history()?;
    if !history.durable_payment_history_supported_v1 {
        return Err(AuthorityError::PolicyDenied);
    }
    let e = history
        .manual_roster_enrollment_extension(&terms.original_enrollment_ref)?
        .ok_or(AuthorityError::Permission)?;
    terms.validate_original(&history.account_policy, e)?;
    let birth = history
        .pending_birth_commit
        .as_ref()
        .ok_or(AuthorityError::CorruptHistory)?;
    e.validate_original_birth(birth)?;
    if history.snapshot.writer_epoch != history.account_policy.initial_writer_epoch
        || history.snapshot.writer_certificate_digest != terms.writer_certificate_digest
    {
        return Err(AuthorityError::RecoveryRequired);
    }
    let mut r = OwnerControlRequest {
        operation_id: String::new(),
        account_id: history.snapshot.account_id.clone(),
        network_profile_id: history.snapshot.network_profile_id.clone(),
        writer_epoch: history.snapshot.writer_epoch,
        expected_head: history.snapshot.head.clone(),
        control: OwnerControl::AdmitDurablePaymentV1 {
            record: Box::new(DurablePaymentAdmissionRecordV1 {
                terms,
                witness_native_review_digest: String::new(),
            }),
        },
    };
    r.operation_id = owner_operation_id(&r)?;
    let review = request_native_review_digest_v1(&r, &birth.request.disclosure)?;
    if let OwnerControl::AdmitDurablePaymentV1 { record } = &mut r.control {
        record.witness_native_review_digest = review;
    }
    Ok(r)
}
impl ReconciledAuthorityHistory {
    pub fn durable_payment_admission_v1(
        &self,
        operation_id: &str,
    ) -> Result<Option<&OwnerControlRequest>> {
        id(operation_id)?;
        let Some(r) = self.owner_controls.get(operation_id) else {
            return Ok(None);
        };
        let OwnerControl::AdmitDurablePaymentV1 { record } = &r.control else {
            return Err(AuthorityError::InvalidBinding);
        };
        let birth = self
            .pending_birth_commit
            .as_ref()
            .ok_or(AuthorityError::CorruptHistory)?;
        let e = self
            .manual_roster_enrollment_extension(&record.terms.original_enrollment_ref)?
            .ok_or(AuthorityError::CorruptHistory)?;
        record.terms.validate_original(&self.account_policy, e)?;
        record.validate_request(r, &birth.request.disclosure)?;
        if !self.contains_operation(operation_id) || !self.contains_head(&r.expected_head) {
            return Err(AuthorityError::CorruptHistory);
        }
        Ok(Some(r))
    }
    /// Complete original permit evidence for this profile only. No empty or
    /// coerced legacy projection, and no current-time check on historical data.
    pub fn durable_payment_online_permits_v1(
        &self,
        admission_operation_id: &str,
    ) -> Result<&[ReservationPermit]> {
        if !self.durable_payment_history_supported_v1 {
            return Err(AuthorityError::PolicyDenied);
        }
        let admission = self
            .durable_payment_admission_v1(admission_operation_id)?
            .ok_or(AuthorityError::Permission)?;
        let OwnerControl::AdmitDurablePaymentV1 { record } = &admission.control else {
            return Err(AuthorityError::CorruptHistory);
        };
        for permit in &self.permits {
            crate::durable_payment_policy_v1::require_exact_reservation_v1(
                &record.terms,
                admission.writer_epoch,
                &permit.request,
            )?;
            permit.matches_request(&permit.request)?;
            if permit.reserved_at_ms < record.terms.valid_from_ms
                || permit.reserved_at_ms >= record.terms.valid_until_ms
                || permit.request.permit_expires_at_ms > record.terms.valid_until_ms
                || !self.contains_head(&permit.committed_head)
                || !self.contains_operation(&record.acquire_operation_id(admission)?)
            {
                return Err(AuthorityError::CorruptHistory);
            }
        }
        Ok(&self.permits)
    }
    pub fn require_durable_payment_session_v1(
        &self,
        admission_operation_id: &str,
        active: &AuthenticatedWriterSession,
    ) -> Result<()> {
        self.durable_payment_online_permits_v1(admission_operation_id)?;
        self.account_use_history
            .require_not_permanently_excluded()?;
        let r = self
            .durable_payment_admission_v1(admission_operation_id)?
            .ok_or(AuthorityError::Permission)?;
        let OwnerControl::AdmitDurablePaymentV1 { record } = &r.control else {
            return Err(AuthorityError::CorruptHistory);
        };
        record.terms.require_live(active.observed_at_ms())?;
        let receipt = active.receipt();
        let sequence = r
            .expected_head
            .sequence
            .checked_add(1)
            .ok_or(AuthorityError::Limit)?;
        if !self.contains_operation(&record.acquire_operation_id(r)?)
            || active.snapshot() != &self.snapshot
            || active.disclosure() != &self.disclosure
            || active.history_digest() != crate::session::history_digest(&self.snapshot)?
            || self.snapshot.writer_status != WriterStatus::Active
            || self.snapshot.writer_epoch != r.writer_epoch
            || self.snapshot.writer_certificate_digest != record.terms.writer_certificate_digest
            || self.snapshot.active_writer_session.as_ref() != Some(receipt)
            || receipt.writer_epoch != r.writer_epoch
            || receipt.writer_certificate_digest != record.terms.writer_certificate_digest
            || receipt.reconciled_head.sequence != sequence
            || !self.contains_head(&receipt.reconciled_head)
            || receipt.acquired_head.sequence != sequence + 1
            || !self.contains_head(&receipt.acquired_head)
            || active.observed_at_ms() >= receipt.expires_at_ms
        {
            return Err(AuthorityError::RecoveryRequired);
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "durable_payment_history_v1_tests.rs"]
mod history_tests;
#[cfg(test)]
#[path = "durable_payment_v1_tests.rs"]
pub(crate) mod tests;
