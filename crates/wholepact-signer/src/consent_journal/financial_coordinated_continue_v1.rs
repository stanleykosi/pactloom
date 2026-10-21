//! Inert exact preparation, not a coordinated approval or a journal transition.
//! The ordinary review facts below do not authenticate Arm, C, H or S. A future
//! original-role final-token join must compare every frozen fact and clock.
//! V2 has a distinct provenance tag and digest domain. Its historical reader
//! binds semantic review and the exact request, not the full rendered presentation
//! or a reusable grant. The live Final must separately bind the presentation.
//! This module does not infer permission from any retained historical payload.
use super::*;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use wholepact_authority::{
    OwnerControl, OwnerControlRequest,
    durable_financial_continuation_v1::{
        FinancialContinuationRecordV1, original_delivery_request_digest_v1,
        prepare_financial_continuation_request_v1,
    },
};

#[cfg(feature = "coordinated-signer-continue")]
#[path = "financial_coordinated_transition_v1.rs"]
mod transition;
#[cfg(feature = "coordinated-signer-continue")]
pub(crate) use transition::{PresentedCoordinatedFinancialContinuationV1, CoordinatedContinuationCommitFailureV1};

const INTENT_VERSION: u16 = 2;
const INTENT_DOMAIN: &str =
    "wholepact:signer-coordinated-financial-continuation-intent-preimage:v2";
const PREPARED_DOMAIN: &str = "wholepact:signer-coordinated-financial-continuation-prepared:v1";

/// A selector in ordinary data, never evidence of the process's actual role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoordinatedContinueSignerRoleV1 {
    Signer1,
    Signer2,
}

/// Proposed review facts only. No constructor of this data can issue permission.
/// The eventual genuine Arm/Final receiver must authenticate all of these facts;
/// accepting their shape during preparation does not authenticate their claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CoordinatedContinueReviewDataV1 {
    pub(crate) coordinator_process_instance: String,
    pub(crate) coordinator_focus_epoch: u64,
    pub(crate) signer_role: CoordinatedContinueSignerRoleV1,
    pub(crate) signer_process_instance: String,
    pub(crate) original_host_process_instance: String,
    pub(crate) signer_principal_id: String,
    pub(crate) signer_image_measurement: String,
    pub(crate) source_identity_digest: String,
    pub(crate) terms_digest: String,
    pub(crate) session_digest: String,
    pub(crate) review_challenge: String,
    pub(crate) review_digest: String,
    pub(crate) reviewed_at_ms: u64,
    pub(crate) expires_at_ms: u64,
    pub(crate) session_expires_at_ms: u64,
}
impl CoordinatedContinueReviewDataV1 {
    fn validate_historical_shape(&self) -> Result<()> {
        for value in [
            &self.coordinator_process_instance,
            &self.signer_process_instance,
            &self.original_host_process_instance,
            &self.signer_image_measurement,
            &self.source_identity_digest,
            &self.terms_digest,
            &self.session_digest,
            &self.review_challenge,
            &self.review_digest,
        ] {
            hash(value)?;
        }
        id(&self.signer_principal_id)?;
        if self.coordinator_focus_epoch == 0
            || self.reviewed_at_ms == 0
            || self.expires_at_ms > self.session_expires_at_ms
            || self
                .expires_at_ms
                .checked_sub(self.reviewed_at_ms)
                .is_none_or(|duration| duration == 0 || duration > 120_000)
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
    fn validate_shape(
        &self,
        source_identity: &str,
        terms_digest: &str,
        original_host_instance: &str,
        now: u64,
    ) -> Result<()> {
        self.validate_historical_shape()?;
        if self.source_identity_digest != source_identity
            || self.terms_digest != terms_digest
            || self.original_host_process_instance != original_host_instance
            || self.reviewed_at_ms > now
            || self.expires_at_ms <= now
        {
            return Err(JournalError::InvalidBinding);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
enum CoordinatedReviewOriginV2 {
    #[serde(rename = "original_coordinator_host_signer_v1")]
    OriginalCoordinatorHostSignerV1,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinatedContinuationProvenanceV2 {
    origin: CoordinatedReviewOriginV2,
    review: CoordinatedContinueReviewDataV1,
    preparation_nonce: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CoordinatedFinancialContinuationIntentV2 {
    version: u16,
    request: OwnerControlRequest,
    owner_certificate_digest: String,
    coordinated_provenance: CoordinatedContinuationProvenanceV2,
}

impl CoordinatedFinancialContinuationIntentV2 {
    pub(super) fn request(&self) -> &OwnerControlRequest {
        &self.request
    }
    pub(super) fn owner_certificate_digest(&self) -> &str {
        &self.owner_certificate_digest
    }
    fn record(&self) -> Result<&FinancialContinuationRecordV1> {
        match &self.request.control {
            OwnerControl::AdmitFinancialContinuationV1 { record } => Ok(record),
            _ => Err(JournalError::InvalidBinding),
        }
    }
    fn seed(&self) -> Result<String> {
        digest(
            INTENT_DOMAIN,
            &(
                INTENT_VERSION,
                &self.record()?.terms,
                &self.owner_certificate_digest,
                &self.coordinated_provenance,
            ),
        )
    }
    fn validate(&self) -> Result<()> {
        let record = self.record()?;
        record
            .validate_request(&self.request, &record.terms.scope.witness)
            .map_err(|_| JournalError::InvalidBinding)?;
        let provenance = &self.coordinated_provenance;
        let review = &provenance.review;
        review.validate_historical_shape()?;
        hash(&provenance.preparation_nonce)?;
        hash(&self.owner_certificate_digest)?;
        if self.version != INTENT_VERSION
            || review.terms_digest
                != record
                    .terms
                    .intent_terms_digest()
                    .map_err(|_| JournalError::InvalidBinding)?
            || review.reviewed_at_ms < record.terms.valid_from_ms
            || review.expires_at_ms > record.terms.valid_until_ms
            || record.signer_continuation_intent_digest != self.seed()?
        {
            return Err(JournalError::InvalidBinding);
        }
        encode(self)?;
        Ok(())
    }
    /// Historical semantic evidence only. Neither the full rendered presentation
    /// nor the genuine single-use Final capability is reconstructed from this row.
    pub(super) fn history_digest(&self) -> Result<String> {
        self.validate()?;
        digest(
            "wholepact:signer-coordinated-financial-continuation-history:v2",
            self,
        )
    }
    pub(super) fn validate_original(&self, c: &Connection) -> Result<()> {
        self.validate()?;
        let terms = &self.record()?.terms;
        let original = authority::durable_delivery_admission_intent_v3::read(
            c,
            &terms.scope.authorization.authorization_id,
        )?
        .ok_or(JournalError::NotFound)?;
        let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } =
            &original.request().control
        else {
            return Err(JournalError::InvalidBinding);
        };
        if record.scope != terms.scope
            || original.request().operation_id != terms.original_delivery_operation_id
            || original_delivery_request_digest_v1(original.request())
                .map_err(|_| JournalError::InvalidBinding)?
                != terms.original_delivery_request_digest
            || original.history_digest()? != terms.original_local_intent_digest
            || original.recipient_intent_digest()? != terms.original_recipient_intent_digest
            || original.enrollment_ref() != terms.original_recipient_enrollment_ref
            || original.manifest_ref() != terms.original_recipient_manifest_ref
            || original.disclosure() != &terms.scope.witness
            || original.owner_certificate_digest() != self.owner_certificate_digest
            || original.recipient_intent().authorized_host_process_instance
                != self
                    .coordinated_provenance
                    .review
                    .original_host_process_instance
        {
            return Err(JournalError::InvalidBinding);
        }
        let enrollment =
            read_enrollment(c, original.enrollment_ref())?.ok_or(JournalError::NotFound)?;
        if enrollment.principal_id() != self.coordinated_provenance.review.signer_principal_id {
            return Err(JournalError::Permission);
        }
        Ok(())
    }
}

/// Immutable source-binding data, authenticated history and actual Host peer,
/// never effect authority or ownership of the original journal/source itself.
/// The caller must retain its actual PreparedOriginalFinancialSourceV1 through
/// preparation and any later final-token join; this ticket cannot replace it.
/// Deliberately no Clone, serde, public constructor, NativeDecision conversion
/// or conversion to the legacy prepared action type. The gated transition child
/// consumes a separate genuine Final; this inert ticket is never sufficient.
pub(crate) struct PreparedCoordinatedFinancialContinuationV1 {
    journal: SignerJournalBinding,
    source_identity: String,
    original_rows_digest: String,
    source_revision: (i64, i64, i64, i64),
    history: ReconciledAuthorityHistory,
    original_host: crate::native_peer::PeerProcess,
    intent: CoordinatedFinancialContinuationIntentV2,
    original_ceiling_ms: u64,
    original_deadline: Instant,
    original_review_deadline: Instant,
    review_deadline: Instant,
    prepared_digest: String,
}
impl PreparedCoordinatedFinancialContinuationV1 {
    pub(crate) fn request(&self) -> &OwnerControlRequest {
        &self.intent.request
    }
    pub(crate) fn prepared_digest(&self) -> &str {
        &self.prepared_digest
    }
    /// This observes only the retained actual Host and fixed preparation clocks.
    /// It does not establish C's identity, an Arm, final admission or source-current
    /// permission. A future final join must revalidate the actual original source.
    pub(crate) fn check_retained_preparation(&self) -> Result<()> {
        self.original_host
            .check_alive()
            .map_err(|_| JournalError::Permission)?;
        let now = now_ms()?;
        if now < self.intent.coordinated_provenance.review.reviewed_at_ms
            || now >= self.intent.coordinated_provenance.review.expires_at_ms
            || now >= self.original_ceiling_ms
            || Instant::now() >= self.review_deadline
            || Instant::now() >= self.original_deadline
        {
            return Err(JournalError::Expired);
        }
        Ok(())
    }
}

#[cfg(feature = "coordinated-financial-workflow-v1")]
fn check_preparation_read_v2(
    read: &wholepact_financial_coordinator_origin::SignerFinancialReadFinalV1,
    source: &FinancialSourceBindingV1,
    terms: &FinancialContinuationTermsV1,
    original_host: &crate::native_peer::PeerProcess,
) -> Result<()> {
    read.check_current().map_err(|_| JournalError::Permission)?;
    let facts = &read.presentation().facts;
    if facts.source_identity_digest != source.identity_digest()
        || facts.terms_digest != terms.intent_terms_digest().map_err(|_| JournalError::InvalidBinding)?
        || facts.original_host_process_instance != original_host.instance()
        || facts.source_expires_at_ms != terms.valid_until_ms
    {
        return Err(JournalError::Permission);
    }
    read.check_current().map_err(|_| JournalError::Permission)
}

impl SignerConsentJournal {
    /// Read-only original enrollment identity, not a consent session or grant.
    /// The actual source pin and complete original19 audit bracket this lookup;
    /// no connection, fence or transaction guard escapes to a review IPC wait.
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(crate) fn coordinated_continue_principal_v1(
        &self,
        source: &FinancialSourceBindingV1,
        terms: &FinancialContinuationTermsV1,
        original_host: &crate::native_peer::PeerProcess,
        read: &wholepact_financial_coordinator_origin::SignerFinancialReadFinalV1,
    ) -> Result<String> {
        let check = || check_preparation_read_v2(read, source, terms, original_host);
        check()?;
        original_host.check_alive().map_err(|_| JournalError::Permission)?;
        terms.require_live(now_ms()?).map_err(|_| JournalError::Expired)?;
        let principal = {
            let _fence = self.authority_fence.read().map_err(|_| JournalError::Permission)?;
            check()?;
            let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
            check()?;
            source.require(self, &c)?;
            check()?;
            source.require_pin(&c)?;
            check()?;
            if source.continuation_digest.is_some() {
                return Err(JournalError::InvalidBinding);
            }
            let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
            check()?;
            durable_born_entry_v1::validate_delivery_v3(&tx, &source.genesis, self.capacity_limits())?;
            check()?;
            if original_rows_digest(&tx)? != source.original_rows_digest {
                return Err(JournalError::Conflict);
            }
            check()?;
            let original = authority::durable_delivery_admission_intent_v3::read(
                &tx, &terms.scope.authorization.authorization_id,
            )?.ok_or(JournalError::NotFound)?;
            check()?;
            let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &original.request().control else {
                return Err(JournalError::InvalidBinding);
            };
            if record.scope != terms.scope
                || original.request().operation_id != terms.original_delivery_operation_id
                || original_delivery_request_digest_v1(original.request()).map_err(|_| JournalError::InvalidBinding)? != terms.original_delivery_request_digest
                || original.history_digest()? != terms.original_local_intent_digest
                || original.recipient_intent_digest()? != terms.original_recipient_intent_digest
                || original.enrollment_ref() != terms.original_recipient_enrollment_ref
                || original.manifest_ref() != terms.original_recipient_manifest_ref
                || original.disclosure() != &terms.scope.witness
                || original.recipient_intent().authorized_host_process_instance != original_host.instance()
            {
                return Err(JournalError::InvalidBinding);
            }
            check()?;
            let enrollment = read_enrollment(&tx, original.enrollment_ref())?.ok_or(JournalError::NotFound)?;
            check()?;
            let principal = enrollment.principal_id().to_owned();
            id(&principal)?;
            source.require(self, &tx)?;
            check()?;
            source.require_pin(&tx)?;
            check()?;
            terms.require_live(now_ms()?).map_err(|_| JournalError::Expired)?;
            original_host.check_alive().map_err(|_| JournalError::Permission)?;
            tx.commit()?;
            check()?;
            source.require(self, &c)?;
            check()?;
            source.require_pin(&c)?;
            check()?;
            principal
        };
        terms.require_live(now_ms()?).map_err(|_| JournalError::Expired)?;
        original_host.check_alive().map_err(|_| JournalError::Permission)?;
        check()?;
        Ok(principal)
    }

    /// Read-only original-row preparation. All guards are local to this call;
    /// none is returned in the inert ticket or retained for a coordinator wait.
    pub(crate) fn prepare_coordinated_financial_continuation_v1(
        &self,
        source: &FinancialSourceBindingV1,
        terms: FinancialContinuationTermsV1,
        history: ReconciledAuthorityHistory,
        original_host: crate::native_peer::PeerProcess,
        review: CoordinatedContinueReviewDataV1,
        original_ceiling_ms: u64,
        original_deadline: Instant,
        retained_review_deadline: Instant,
    ) -> Result<PreparedCoordinatedFinancialContinuationV1> {
        self.prepare_coordinated_financial_continuation_inner_v1(
            source, terms, history, original_host, review, original_ceiling_ms, original_deadline, retained_review_deadline,
            #[cfg(feature = "coordinated-financial-workflow-v1")]
            None,
        )
    }

    #[cfg(feature = "coordinated-financial-workflow-v1")]
    pub(crate) fn prepare_coordinated_financial_continuation_from_read_v2(
        &self,
        source: &FinancialSourceBindingV1,
        terms: FinancialContinuationTermsV1,
        history: ReconciledAuthorityHistory,
        original_host: crate::native_peer::PeerProcess,
        review: CoordinatedContinueReviewDataV1,
        original_ceiling_ms: u64,
        original_deadline: Instant,
        retained_review_deadline: Instant,
        read: &wholepact_financial_coordinator_origin::SignerFinancialReadFinalV1,
    ) -> Result<PreparedCoordinatedFinancialContinuationV1> {
        self.prepare_coordinated_financial_continuation_inner_v1(
            source, terms, history, original_host, review, original_ceiling_ms, original_deadline, retained_review_deadline, Some(read),
        )
    }

    fn prepare_coordinated_financial_continuation_inner_v1(
        &self,
        source: &FinancialSourceBindingV1,
        terms: FinancialContinuationTermsV1,
        history: ReconciledAuthorityHistory,
        original_host: crate::native_peer::PeerProcess,
        review: CoordinatedContinueReviewDataV1,
        original_ceiling_ms: u64,
        original_deadline: Instant,
        retained_review_deadline: Instant,
        #[cfg(feature = "coordinated-financial-workflow-v1")]
        read: Option<&wholepact_financial_coordinator_origin::SignerFinancialReadFinalV1>,
    ) -> Result<PreparedCoordinatedFinancialContinuationV1> {
        macro_rules! check_read {
            () => {
                #[cfg(feature = "coordinated-financial-workflow-v1")]
                if let Some(read) = read {
                    check_preparation_read_v2(read, source, &terms, &original_host)?;
                }
            };
        }
        macro_rules! check_read_current {
            () => {
                #[cfg(feature = "coordinated-financial-workflow-v1")]
                if let Some(read) = read {
                    read.check_current().map_err(|_| JournalError::Permission)?;
                }
            };
        }
        check_read!();
        original_host
            .check_alive()
            .map_err(|_| JournalError::Permission)?;
        let now = now_ms()?;
        let terms_digest = terms
            .intent_terms_digest()
            .map_err(|_| JournalError::InvalidBinding)?;
        review.validate_shape(
            source.identity_digest(),
            &terms_digest,
            original_host.instance(),
            now,
        )?;
        terms.require_live(now).map_err(|_| JournalError::Expired)?;
        if terms.valid_until_ms != original_ceiling_ms
            || review.reviewed_at_ms < terms.valid_from_ms
            || review.expires_at_ms > original_ceiling_ms
        {
            return Err(JournalError::InvalidBinding);
        }
        let review_deadline = Instant::now()
            .checked_add(Duration::from_millis(review.expires_at_ms - now))
            .ok_or(JournalError::InvalidBinding)?
            .min(retained_review_deadline)
            .min(original_deadline);
        if Instant::now() >= review_deadline {
            return Err(JournalError::Expired);
        }
        let prepared = {
            let _fence = self
                .authority_fence
                .read()
                .map_err(|_| JournalError::Permission)?;
            check_read!();
            let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
            check_read!();
            source.require(self, &c)?;
            check_read!();
            source.require_pin(&c)?;
            check_read!();
            let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
            check_read!();
            durable_born_entry_v1::validate_delivery_v3(
                &tx,
                &source.genesis,
                self.capacity_limits(),
            )?;
            check_read!();
            if original_rows_digest(&tx)? != source.original_rows_digest {
                return Err(JournalError::Conflict);
            }
            check_read!();
            let original = authority::durable_delivery_admission_intent_v3::read(
                &tx,
                &terms.scope.authorization.authorization_id,
            )?
            .ok_or(JournalError::NotFound)?;
            check_read!();
            let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } =
                &original.request().control
            else {
                return Err(JournalError::InvalidBinding);
            };
            let invalid = |_| JournalError::InvalidBinding;
            if record.scope != terms.scope
                || original.request().operation_id != terms.original_delivery_operation_id
                || original_delivery_request_digest_v1(original.request()).map_err(invalid)?
                    != terms.original_delivery_request_digest
                || original.history_digest()? != terms.original_local_intent_digest
                || original.recipient_intent_digest()? != terms.original_recipient_intent_digest
                || original.enrollment_ref() != terms.original_recipient_enrollment_ref
                || original.manifest_ref() != terms.original_recipient_manifest_ref
                || original.disclosure() != &terms.scope.witness
                || original.recipient_intent().authorized_host_process_instance
                    != original_host.instance()
            {
                return Err(JournalError::InvalidBinding);
            }
            check_read!();
            let enrollment =
                read_enrollment(&tx, original.enrollment_ref())?.ok_or(JournalError::NotFound)?;
            check_read!();
            if enrollment.principal_id() != review.signer_principal_id {
                return Err(JournalError::Permission);
            }
            let provenance = CoordinatedContinuationProvenanceV2 {
                origin: CoordinatedReviewOriginV2::OriginalCoordinatorHostSignerV1,
                review,
                preparation_nonce: random_id()?,
            };
            let owner_certificate_digest = original.owner_certificate_digest().to_owned();
            let seed = digest(
                INTENT_DOMAIN,
                &(
                    INTENT_VERSION,
                    &terms,
                    &owner_certificate_digest,
                    &provenance,
                ),
            )?;
            check_read!();
            let request = prepare_financial_continuation_request_v1(terms, seed, &history)
                .map_err(invalid)?;
            let intent = CoordinatedFinancialContinuationIntentV2 {
                version: INTENT_VERSION,
                request,
                owner_certificate_digest,
                coordinated_provenance: provenance,
            };
            let source_revision = (
                source.revision.data_version,
                source.revision.total_changes,
                source.revision.schema_version,
                source.revision.user_version,
            );
            let prepared_digest = digest(
                PREPARED_DOMAIN,
                &(
                    &intent,
                    &source.source_digest,
                    &source.original_rows_digest,
                    source_revision,
                    history.history_digest().map_err(invalid)?,
                    history.snapshot(),
                    original_host.instance(),
                    original_ceiling_ms,
                ),
            )?;
            check_read_current!();
            source.require(self, &tx)?;
            check_read_current!();
            source.require_pin(&tx)?;
            check_read_current!();
            tx.commit()?;
            check_read_current!();
            source.require_pin(&c)?;
            check_read_current!();
            PreparedCoordinatedFinancialContinuationV1 {
                journal: self.binding(),
                source_identity: source.source_digest.clone(),
                original_rows_digest: source.original_rows_digest.clone(),
                source_revision,
                history,
                original_host,
                intent,
                original_ceiling_ms,
                original_deadline,
                original_review_deadline: retained_review_deadline,
                review_deadline,
                prepared_digest,
            }
        };
        prepared.check_retained_preparation()?;
        check_read_current!();
        Ok(prepared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> CoordinatedContinueReviewDataV1 {
        CoordinatedContinueReviewDataV1 {
            coordinator_process_instance: "01".repeat(32),
            coordinator_focus_epoch: 7,
            signer_role: CoordinatedContinueSignerRoleV1::Signer1,
            signer_process_instance: "02".repeat(32),
            original_host_process_instance: "03".repeat(32),
            signer_principal_id: "inert-shape-fixture".into(),
            signer_image_measurement: "04".repeat(32),
            source_identity_digest: "05".repeat(32),
            terms_digest: "06".repeat(32),
            session_digest: "07".repeat(32),
            review_challenge: "08".repeat(32),
            review_digest: "09".repeat(32),
            reviewed_at_ms: 1_000,
            expires_at_ms: 121_000,
            session_expires_at_ms: 300_000,
        }
    }
    fn valid(value: &CoordinatedContinueReviewDataV1) -> Result<()> {
        value.validate_shape(&"05".repeat(32), &"06".repeat(32), &"03".repeat(32), 2_000)
    }
    #[test]
    fn inert_review_shape_rejects_changed_bindings_and_bounds() {
        let original = data();
        assert!(valid(&original).is_ok());
        for mutation in 0..8 {
            let mut changed = original.clone();
            match mutation {
                0 => changed.source_identity_digest = "ff".repeat(32),
                1 => changed.terms_digest = "ff".repeat(32),
                2 => changed.original_host_process_instance = "ff".repeat(32),
                3 => changed.coordinator_focus_epoch = 0,
                4 => changed.reviewed_at_ms = 2_001,
                5 => changed.expires_at_ms = 2_000,
                6 => changed.expires_at_ms = 121_001,
                _ => changed.session_expires_at_ms = 120_999,
            }
            assert!(valid(&changed).is_err());
        }
    }
    #[test]
    fn coordinated_provenance_is_tagged_and_domain_separated_from_native_v1() {
        let provenance = CoordinatedContinuationProvenanceV2 {
            origin: CoordinatedReviewOriginV2::OriginalCoordinatorHostSignerV1,
            review: data(),
            preparation_nonce: "0a".repeat(32),
        };
        let encoded = serde_json::to_value(&provenance).unwrap();
        assert_eq!(INTENT_VERSION, 2);
        assert_eq!(encoded["origin"], "original_coordinator_host_signer_v1");
        assert!(encoded.get("native_review_digest").is_none());
        assert!(encoded.get("permission_generation").is_none());
        assert_ne!(
            digest(INTENT_DOMAIN, &provenance).unwrap(),
            digest(
                "wholepact:signer-financial-continuation-intent-preimage:v1",
                &provenance
            )
            .unwrap(),
        );
    }
    #[test]
    fn every_review_identity_and_challenge_is_inside_the_frozen_preimage() {
        let original = data();
        let original_digest = digest(INTENT_DOMAIN, &original).unwrap();
        for mutation in 0..15 {
            let mut changed = original.clone();
            match mutation {
                0 => changed.coordinator_process_instance = "ff".repeat(32),
                1 => changed.coordinator_focus_epoch += 1,
                2 => changed.signer_role = CoordinatedContinueSignerRoleV1::Signer2,
                3 => changed.signer_process_instance = "ff".repeat(32),
                4 => changed.original_host_process_instance = "ff".repeat(32),
                5 => changed.signer_principal_id.push('x'),
                6 => changed.signer_image_measurement = "ff".repeat(32),
                7 => changed.source_identity_digest = "ff".repeat(32),
                8 => changed.terms_digest = "ff".repeat(32),
                9 => changed.session_digest = "ff".repeat(32),
                10 => changed.review_challenge = "ff".repeat(32),
                11 => changed.review_digest = "ff".repeat(32),
                12 => changed.reviewed_at_ms += 1,
                13 => changed.expires_at_ms -= 1,
                _ => changed.session_expires_at_ms -= 1,
            }
            assert_ne!(original_digest, digest(INTENT_DOMAIN, &changed).unwrap());
        }
    }
}
