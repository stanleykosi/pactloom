//! Exact immutable financial admission intent, committed before remote mutation.
//! Retained rows are historical evidence only. They cannot recreate a Pending,
//! Approval, native decision, writer session, reservation, or financial server.
use super::*;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use wholepact_authority::{
    account_use_link::account_use_witness_origin_digest,
    durable_payment_v1::DurablePaymentAdmissionRecordV1, OwnerControl, OwnerControlRequest,
    WitnessDisclosureDescriptor,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurablePaymentAdmissionIntentV1 {
    version: u16,
    request: OwnerControlRequest,
    disclosure: WitnessDisclosureDescriptor,
    owner_certificate_digest: String,
    enrollment_ref: String,
    manifest_ref: String,
    native_receipt: NativeConsentReceipt,
    native_review_digest: String,
}
/// Data-only validated history. No Deserialize, public fields, approval factory,
/// or conversion to a live decision is exposed outside this private reader.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RetainedDurablePaymentAdmissionIntentV1(DurablePaymentAdmissionIntentV1);
impl RetainedDurablePaymentAdmissionIntentV1 {
    pub(crate) fn request(&self) -> &OwnerControlRequest {
        &self.0.request
    }
    pub(crate) fn disclosure(&self) -> &WitnessDisclosureDescriptor {
        &self.0.disclosure
    }
    pub(crate) fn owner_certificate_digest(&self) -> &str {
        &self.0.owner_certificate_digest
    }
    pub(crate) fn enrollment_ref(&self) -> &str {
        &self.0.enrollment_ref
    }
    pub(crate) fn manifest_ref(&self) -> &str {
        &self.0.manifest_ref
    }
    pub(crate) fn native_receipt(&self) -> &NativeConsentReceipt {
        &self.0.native_receipt
    }
    pub(crate) fn native_review_digest(&self) -> &str {
        &self.0.native_review_digest
    }
    pub(crate) fn history_digest(&self) -> Result<String> {
        self.0.validate()?;
        digest(
            "wholepact:signer-durable-payment-admission-intent-history:v1",
            &self.0,
        )
    }
}
fn invalid(_: impl std::fmt::Display) -> JournalError {
    JournalError::InvalidBinding
}
fn record(request: &OwnerControlRequest) -> Result<&DurablePaymentAdmissionRecordV1> {
    match &request.control {
        OwnerControl::AdmitDurablePaymentV1 { record } => Ok(record),
        _ => Err(JournalError::InvalidBinding),
    }
}
impl DurablePaymentAdmissionIntentV1 {
    fn review_digest(&self) -> Result<String> {
        digest(
            "wholepact:signer-durable-payment-admission-review:v1",
            &(
                self.version,
                &self.request,
                &self.disclosure,
                &self.owner_certificate_digest,
                &self.enrollment_ref,
                &self.manifest_ref,
                &self.native_receipt,
            ),
        )
    }
    fn request_digest(&self) -> Result<String> {
        digest(
            "wholepact:signer-durable-payment-admission-request:v1",
            &self.request,
        )
    }
    fn validate(&self) -> Result<()> {
        self.disclosure.validate().map_err(invalid)?;
        record(&self.request)?
            .validate_request(&self.request, &self.disclosure)
            .map_err(invalid)?;
        self.native_receipt.validate()?;
        for h in [
            &self.owner_certificate_digest,
            &self.enrollment_ref,
            &self.manifest_ref,
            &self.native_review_digest,
        ] {
            hash(h)?;
        }
        if self.version != 1
            || self.native_review_digest != self.review_digest()?
            || self.native_receipt.writer_epoch() != self.request.writer_epoch
        {
            return Err(JournalError::InvalidBinding);
        }
        // The request's original witness-native review and this current local
        // signer-native privacy review deliberately have different domains.
        Ok(())
    }
    fn same_remote_intent(&self, other: &Self) -> bool {
        self.request == other.request
            && self.disclosure == other.disclosure
            && self.owner_certificate_digest == other.owner_certificate_digest
    }
}

/// Validate historical links without any present-time receipt/intent expiry
/// test. Fresh access/dispatch requires independent actual runtime/native owners.
fn validate_original_rows(c: &Connection, intent: &DurablePaymentAdmissionIntentV1) -> Result<()> {
    intent.validate()?;
    let request = &intent.request;
    let terms = &record(request)?.terms;
    let account = storage::read_account(c)?;
    let stored = account_use_storage::inspect(c, &account.account_id)?;
    let genesis = stored.genesis().ok_or(JournalError::InvalidBinding)?;
    let enrollment =
        storage::read_enrollment(c, &intent.enrollment_ref)?.ok_or(JournalError::NotFound)?;
    let manifest =
        storage::read_manifest(c, &intent.manifest_ref)?.ok_or(JournalError::NotFound)?;
    let proposal = manifest.proposal()?;
    if account.account_id != request.account_id
        || request.writer_epoch > account.writer_epoch
        || genesis.identity.account_id != terms.identity.account_id
        || genesis.identity.full_viewing_key_digest != terms.identity.full_viewing_key_digest
        || genesis.identity.network_profile_id != terms.identity.network_profile_id
        || genesis.identity.derivation_domain != terms.identity.derivation_domain
        || genesis.digest().map_err(invalid)? != terms.original_genesis_digest
        || genesis.owner_certificate_digest != intent.owner_certificate_digest
        || genesis.witness_id != intent.disclosure.witness_id
        || genesis.witness_origin_digest
            != account_use_witness_origin_digest(&intent.disclosure).map_err(invalid)?
        || enrollment.account_id() != request.account_id
        || enrollment.account_fvk_digest() != terms.identity.full_viewing_key_digest
        || enrollment.terms.network_profile_id != request.network_profile_id
        || enrollment.agreement_id() != terms.fixed.agreement_id
        || manifest.enrollment_ref() != intent.enrollment_ref
        || manifest.terms.account_id != request.account_id
        || manifest.terms.principal_id != enrollment.principal_id()
        || proposal.input().proposal_id != terms.fixed.proposal_id
        || proposal.manifest().agreement.revision != terms.fixed.revision
        || proposal.proposal_digest() != terms.fixed.proposal_digest
        || proposal.manifest_digest() != terms.fixed.manifest_digest
        || !storage::same_native_origin(enrollment.receipt(), manifest.receipt())
        || !storage::same_native_origin(enrollment.receipt(), &intent.native_receipt)
    {
        return Err(JournalError::InvalidBinding);
    }
    enrollment.transport().validate_scope(
        enrollment.account_id(),
        enrollment.agreement_id(),
        enrollment.participant_id(),
        Some(proposal.manifest_digest()),
    )?;
    Ok(())
}
fn read(
    c: &Connection,
    authorization_id: &str,
) -> Result<Option<RetainedDurablePaymentAdmissionIntentV1>> {
    id(authorization_id)?;
    let row: Option<(String,String,String,String,String)> = c.query_row(
        "SELECT operation_id,request_digest,enrollment_ref,manifest_ref,payload FROM signer_durable_payment_admission_intents WHERE authorization_id=?1",
        [authorization_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    ).optional()?;
    row.map(
        |(operation, request_digest, enrollment, manifest, payload)| {
            let intent: DurablePaymentAdmissionIntentV1 = decode(payload.clone())?;
            if intent.request.operation_id != operation
                || record(&intent.request)?.terms.authorization_id != authorization_id
                || intent.request_digest()? != request_digest
                || intent.enrollment_ref != enrollment
                || intent.manifest_ref != manifest
                || encode(&intent)?.as_str() != payload
            {
                return Err(JournalError::InvalidBinding);
            }
            validate_original_rows(c, &intent)?;
            Ok(RetainedDurablePaymentAdmissionIntentV1(intent))
        },
    )
    .transpose()
}
pub(crate) fn read_all(
    c: &Connection,
    account: &str,
) -> Result<Vec<RetainedDurablePaymentAdmissionIntentV1>> {
    if storage::read_account(c)?.account_id != account {
        return Err(JournalError::InvalidBinding);
    }
    let mut q = c.prepare("SELECT authorization_id FROM signer_durable_payment_admission_intents ORDER BY authorization_id LIMIT 100001")?;
    let ids = q
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if ids.len() as u64 > MAX_BACKUP_ROWS {
        return Err(JournalError::Limit);
    }
    ids.into_iter()
        .map(|id| read(c, &id)?.ok_or(JournalError::NotFound))
        .collect()
}
pub(crate) fn read_durable_payment_admission_intents_v1(
    c: &Connection,
) -> Result<Vec<RetainedDurablePaymentAdmissionIntentV1>> {
    read_all(c, &storage::read_account(c)?.account_id)
}
pub(crate) fn validate_rows(c: &Connection) -> Result<()> {
    read_durable_payment_admission_intents_v1(c).map(|_| ())
}

#[cfg(all(
    feature = "durable-proposal",
    feature = "native-ui",
    target_os = "linux"
))]
mod issuance {
    use super::*;
    struct PreparedIntent {
        account: SignerAccountState,
        intent: DurablePaymentAdmissionIntentV1,
    }
    pub(crate) struct PreparedDurablePaymentAdmissionIntentV1(Pending<PreparedIntent>);
    pub(crate) struct ApprovedDurablePaymentAdmissionIntentV1(Approval<PreparedIntent>);
    impl PreparedDurablePaymentAdmissionIntentV1 {
        pub(crate) fn digest(&self) -> &str {
            &self.0.review_digest
        }
        pub(crate) fn review_digest(&self) -> &str {
            self.digest()
        }
        pub(crate) fn display(&self) -> Result<String> {
            let _lease = self.0.session.read()?;
            serde_json::to_string_pretty(&self.0.record.intent).map_err(invalid)
        }
    }
    fn current_rows(
        c: &Connection,
        intent: &DurablePaymentAdmissionIntentV1,
        lease: &ReadLease<'_>,
    ) -> Result<()> {
        validate_original_rows(c, intent)?;
        let enrollment =
            storage::read_enrollment(c, &intent.enrollment_ref)?.ok_or(JournalError::NotFound)?;
        let manifest =
            storage::read_manifest(c, &intent.manifest_ref)?.ok_or(JournalError::NotFound)?;
        if enrollment.principal_id() != lease.principal
            || manifest.terms.principal_id != lease.principal
        {
            return Err(JournalError::Permission);
        }
        lease.require_spending_decision(enrollment.receipt())?;
        lease.require_spending_decision(manifest.receipt())?;
        lease.require_spending_decision(&intent.native_receipt)?;
        let account_use = account_use_storage::inspect(c, &intent.request.account_id)?;
        if account_use.exclusion().is_some() || account_use.witness_ack().is_some() {
            return Err(JournalError::Permission);
        }
        let terms = &record(&intent.request)?.terms;
        let now = now_ms()?;
        if now < terms.valid_from_ms || now >= terms.valid_until_ms {
            return Err(JournalError::Expired);
        }
        Ok(())
    }
    impl SignerConsentSession {
        pub(crate) fn prepare_durable_payment_admission_intent_v1(
            &self,
            journal: &SignerConsentJournal,
            request: OwnerControlRequest,
            disclosure: WitnessDisclosureDescriptor,
            owner_certificate_digest: &str,
            enrollment_ref: &str,
            manifest_ref: &str,
        ) -> Result<PreparedDurablePaymentAdmissionIntentV1> {
            let account = journal.account_state()?;
            let lease = self.read_lease(&journal.binding(), &account)?;
            if account.recovery_required {
                return Err(JournalError::RecoveryRequired);
            }
            let terms = &record(&request)?.terms;
            let fixed: wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1 =
                serde_json::from_value(serde_json::to_value(&terms.fixed).map_err(invalid)?)
                    .map_err(invalid)?;
            if crate::authority_bridge::durable_proposal_v1::manual_authorization_id(
                &fixed,
                &account.account_id,
            )
            .map_err(invalid)?
                != terms.authorization_id
            {
                return Err(JournalError::InvalidBinding);
            }
            let mut intent = DurablePaymentAdmissionIntentV1 {
                version: 1,
                request,
                disclosure,
                owner_certificate_digest: owner_certificate_digest.into(),
                enrollment_ref: enrollment_ref.into(),
                manifest_ref: manifest_ref.into(),
                native_receipt: self.receipt()?,
                native_review_digest: String::new(),
            };
            intent.native_review_digest = intent.review_digest()?;
            {
                let _fence = journal
                    .authority_fence
                    .read()
                    .map_err(|_| JournalError::Permission)?;
                let mut c = journal
                    .connection
                    .lock()
                    .map_err(|_| JournalError::Database)?;
                journal.database_identity.check_current(&c)?;
                let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
                storage::check_account(&tx, &account)?;
                storage::verify_schema(&tx)?;
                current_rows(&tx, &intent, &lease)?;
                if let Some(old) = read(&tx, &record(&intent.request)?.terms.authorization_id)? {
                    if !old.0.same_remote_intent(&intent) {
                        return Err(JournalError::Conflict);
                    }
                }
                journal.database_identity.check_current(&tx)?;
                lease.check_current()?;
                tx.commit()?;
            }
            let review_digest = intent.native_review_digest.clone();
            Ok(PreparedDurablePaymentAdmissionIntentV1(Pending::new(
                PreparedIntent { account, intent },
                review_digest,
                &self.inner,
            )))
        }
        pub(crate) fn approve_durable_payment_admission_intent_v1(
            &self,
            prepared: PreparedDurablePaymentAdmissionIntentV1,
            decision: NativeConsentDecision,
        ) -> Result<ApprovedDurablePaymentAdmissionIntentV1> {
            Ok(ApprovedDurablePaymentAdmissionIntentV1(
                prepared.0.approve(self, decision)?,
            ))
        }
    }
    impl SignerConsentJournal {
        pub(crate) fn retain_durable_payment_admission_intent_v1(
            &self,
            approved: ApprovedDurablePaymentAdmissionIntentV1,
            mut check_current: impl FnMut() -> Result<()>,
        ) -> Result<RetainedDurablePaymentAdmissionIntentV1> {
            let a = approved.0;
            let r = &a.record;
            let lease = a.lease(&self.binding(), &r.account, &r.intent.native_receipt)?;
            let _fence = self
                .authority_fence
                .write()
                .map_err(|_| JournalError::Permission)?;
            let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
            self.database_identity.check_current(&c)?;
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            storage::check_account(&tx, &r.account)?;
            current_rows(&tx, &r.intent, &lease)?;
            check_current()?; // deny-only; MUST NOT reacquire journal/session fences.
            let auth = &record(&r.intent.request)?.terms.authorization_id;
            let retained = if let Some(old) = read(&tx, auth)? {
                if !old.0.same_remote_intent(&r.intent) {
                    return Err(JournalError::Conflict);
                }
                old // Keep FIRST native receipt/local refs, never overwrite them.
            } else {
                let raw = encode(&r.intent)?;
                tx.execute("INSERT INTO signer_durable_payment_admission_intents(operation_id,authorization_id,request_digest,enrollment_ref,manifest_ref,payload) VALUES(?1,?2,?3,?4,?5,?6)",params![
                    r.intent.request.operation_id,auth,r.intent.request_digest()?,r.intent.enrollment_ref,r.intent.manifest_ref,raw.as_str()
                ])?;
                RetainedDurablePaymentAdmissionIntentV1(r.intent.clone())
            };
            storage::bounded(&tx, self.capacity_limits())?;
            current_rows(&tx, &r.intent, &lease)?;
            self.database_identity.check_current(&tx)?;
            check_current()?;
            lease.check_current()?;
            tx.commit()?;
            Ok(retained)
        }
        pub(crate) fn durable_payment_admission_intent_v1(
            &self,
            authorization_id: &str,
            session: &SignerConsentSession,
        ) -> Result<Option<RetainedDurablePaymentAdmissionIntentV1>> {
            let account = self.account_state()?;
            let lease = session.read_lease(&self.binding(), &account)?;
            let _fence = self
                .authority_fence
                .read()
                .map_err(|_| JournalError::Permission)?;
            let mut c = self.connection.lock().map_err(|_| JournalError::Database)?;
            self.database_identity.check_current(&c)?;
            let tx = c.transaction_with_behavior(TransactionBehavior::Deferred)?;
            storage::check_account(&tx, &account)?;
            let retained = read(&tx, authorization_id)?;
            if let Some(row) = &retained {
                let e = storage::read_enrollment(&tx, row.enrollment_ref())?
                    .ok_or(JournalError::NotFound)?;
                if e.principal_id() != lease.principal {
                    return Err(JournalError::Permission);
                }
            }
            self.database_identity.check_current(&tx)?;
            lease.check_current()?;
            tx.commit()?;
            Ok(retained)
        }
    }
}
#[cfg(all(
    feature = "durable-proposal",
    feature = "native-ui",
    target_os = "linux"
))]
pub(crate) use issuance::{
    ApprovedDurablePaymentAdmissionIntentV1, PreparedDurablePaymentAdmissionIntentV1,
};

#[cfg(all(
    test,
    feature = "durable-proposal",
    feature = "native-ui",
    target_os = "linux"
))]
#[path = "durable_payment_admission_intent_v1_tests.rs"]
mod tests;
