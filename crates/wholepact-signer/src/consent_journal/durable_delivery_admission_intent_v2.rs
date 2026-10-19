//! Exact immutable financial admission intent, committed before remote mutation.
//! Retained rows are historical evidence only. They cannot recreate a Pending,
//! Approval, native decision, writer session, reservation, or financial server.
use super::*;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use wholepact_authority::{
    account_use_link::account_use_witness_origin_digest,
    durable_delivery_admission_v2::DurableDeliveryAdmissionRecordV2, OwnerControl,
    OwnerControlRequest, WitnessDisclosureDescriptor,
};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableDeliveryAdmissionIntentV2 {
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
pub(crate) struct RetainedDurableDeliveryAdmissionIntentV2(DurableDeliveryAdmissionIntentV2);
impl RetainedDurableDeliveryAdmissionIntentV2 {
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
            "wholepact:signer-durable-delivery-admission-intent-history:v2",
            &self.0,
        )
    }
}
fn invalid(_: impl std::fmt::Display) -> JournalError {
    JournalError::InvalidBinding
}
fn record(request: &OwnerControlRequest) -> Result<&DurableDeliveryAdmissionRecordV2> {
    match &request.control {
        OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } => Ok(record),
        _ => Err(JournalError::InvalidBinding),
    }
}
impl DurableDeliveryAdmissionIntentV2 {
    fn review_digest(&self) -> Result<String> {
        digest(
            "wholepact:signer-durable-delivery-admission-review:v2",
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
            "wholepact:signer-durable-delivery-admission-request:v2",
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
        if self.version != 2
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
fn validate_original_rows(c: &Connection, intent: &DurableDeliveryAdmissionIntentV2) -> Result<()> {
    intent.validate()?;
    let request = &intent.request;
    let terms = &record(request)?.scope.authorization;
    let account = storage::read_account(c)?;
    let stored = account_use_storage::inspect(c, &account.account_id)?;
    let genesis = stored.genesis().ok_or(JournalError::InvalidBinding)?;
    let enrollment =
        storage::read_enrollment(c, &intent.enrollment_ref)?.ok_or(JournalError::NotFound)?;
    let manifest =
        storage::read_manifest(c, &intent.manifest_ref)?.ok_or(JournalError::NotFound)?;
    let proposal = manifest.proposal()?;
    if record(request)?.scope.accepted_manifest_ref != intent.manifest_ref
        || record(request)?.scope.original_writer_epoch != request.writer_epoch
        || record(request)?.scope.witness != intent.disclosure
        || account.account_id != request.account_id
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
pub(crate) fn read(
    c: &Connection,
    authorization_id: &str,
) -> Result<Option<RetainedDurableDeliveryAdmissionIntentV2>> {
    id(authorization_id)?;
    let row: Option<(String,String,String,String,String)> = c.query_row(
        "SELECT operation_id,request_digest,enrollment_ref,manifest_ref,payload FROM signer_durable_payment_admission_intents WHERE authorization_id=?1",
        [authorization_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    ).optional()?;
    row.map(
        |(operation, request_digest, enrollment, manifest, payload)| {
            let intent: DurableDeliveryAdmissionIntentV2 = decode(payload.clone())?;
            if intent.request.operation_id != operation
                || record(&intent.request)?
                    .scope
                    .authorization
                    .authorization_id
                    != authorization_id
                || intent.request_digest()? != request_digest
                || intent.enrollment_ref != enrollment
                || intent.manifest_ref != manifest
                || encode(&intent)?.as_str() != payload
            {
                return Err(JournalError::InvalidBinding);
            }
            validate_original_rows(c, &intent)?;
            Ok(RetainedDurableDeliveryAdmissionIntentV2(intent))
        },
    )
    .transpose()
}
pub(crate) fn read_all(
    c: &Connection,
    account: &str,
) -> Result<Vec<RetainedDurableDeliveryAdmissionIntentV2>> {
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
pub(crate) fn read_durable_delivery_admission_intents_v2(
    c: &Connection,
) -> Result<Vec<RetainedDurableDeliveryAdmissionIntentV2>> {
    read_all(c, &storage::read_account(c)?.account_id)
}
pub(crate) fn validate_rows(c: &Connection) -> Result<()> {
    read_durable_delivery_admission_intents_v2(c).map(|_| ())
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
        intent: DurableDeliveryAdmissionIntentV2,
    }
    pub(crate) struct PreparedDurableDeliveryAdmissionIntentV2(Pending<PreparedIntent>);
    pub(crate) struct ApprovedDurableDeliveryAdmissionIntentV2(Approval<PreparedIntent>);
    impl PreparedDurableDeliveryAdmissionIntentV2 {
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
        intent: &DurableDeliveryAdmissionIntentV2,
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
        let terms = &record(&intent.request)?.scope.authorization;
        let now = now_ms()?;
        let delivery = &record(&intent.request)?.scope.delivery;
        if now < terms.valid_from_ms
            || now >= terms.valid_until_ms
            || now < delivery.valid_from_ms
            || now >= delivery.valid_until_ms
        {
            return Err(JournalError::Expired);
        }
        Ok(())
    }
    impl SignerConsentSession {
        pub(crate) fn prepare_durable_delivery_admission_intent_v2(
            &self,
            journal: &SignerConsentJournal,
            request: OwnerControlRequest,
            disclosure: WitnessDisclosureDescriptor,
            owner_certificate_digest: &str,
            enrollment_ref: &str,
            manifest_ref: &str,
        ) -> Result<PreparedDurableDeliveryAdmissionIntentV2> {
            let account = journal.account_state()?;
            let lease = self.read_lease(&journal.binding(), &account)?;
            if account.recovery_required {
                return Err(JournalError::RecoveryRequired);
            }
            let terms = &record(&request)?.scope.authorization;
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
            let mut intent = DurableDeliveryAdmissionIntentV2 {
                version: 2,
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
                if let Some(old) = read(
                    &tx,
                    &record(&intent.request)?
                        .scope
                        .authorization
                        .authorization_id,
                )? {
                    if !old.0.same_remote_intent(&intent) {
                        return Err(JournalError::Conflict);
                    }
                }
                journal.database_identity.check_current(&tx)?;
                lease.check_current()?;
                tx.commit()?;
            }
            let review_digest = intent.native_review_digest.clone();
            Ok(PreparedDurableDeliveryAdmissionIntentV2(Pending::new(
                PreparedIntent { account, intent },
                review_digest,
                &self.inner,
            )))
        }
        pub(crate) fn approve_durable_delivery_admission_intent_v2(
            &self,
            prepared: PreparedDurableDeliveryAdmissionIntentV2,
            decision: NativeConsentDecision,
        ) -> Result<ApprovedDurableDeliveryAdmissionIntentV2> {
            Ok(ApprovedDurableDeliveryAdmissionIntentV2(
                prepared.0.approve(self, decision)?,
            ))
        }
    }
    impl SignerConsentJournal {
        pub(crate) fn retain_durable_delivery_admission_intent_v2(
            &self,
            approved: ApprovedDurableDeliveryAdmissionIntentV2,
            mut check_current: impl FnMut() -> Result<()>,
        ) -> Result<RetainedDurableDeliveryAdmissionIntentV2> {
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
            let auth = &record(&r.intent.request)?
                .scope
                .authorization
                .authorization_id;
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
                RetainedDurableDeliveryAdmissionIntentV2(r.intent.clone())
            };
            storage::bounded(&tx, self.capacity_limits())?;
            current_rows(&tx, &r.intent, &lease)?;
            self.database_identity.check_current(&tx)?;
            check_current()?;
            lease.check_current()?;
            tx.commit()?;
            Ok(retained)
        }
        pub(crate) fn durable_delivery_admission_intent_v2(
            &self,
            authorization_id: &str,
            session: &SignerConsentSession,
        ) -> Result<Option<RetainedDurableDeliveryAdmissionIntentV2>> {
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
    ApprovedDurableDeliveryAdmissionIntentV2, PreparedDurableDeliveryAdmissionIntentV2,
};

#[cfg(all(
    test,
    feature = "durable-proposal",
    feature = "native-ui",
    target_os = "linux"
))]
mod tests {
    //! Isolated synthetic journal/Pending predicates. These fixtures are inert and
    //! never invoke a native window, wallet, witness server, or admission transport.
    use super::*;
    use wholepact_authority::durable_delivery_scope_v2::*;
    use wholepact_core::manual_construction::PreconstructionProvider;
    use crate::consent_journal::authority::fixture;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    use wholepact_authority::{
        account_use::{AccountUseGenesis, AccountUseIdentity},
        durable_payment_v1::{DurableFixedCandidateBindingV1, DurablePaymentAdmissionTermsV1},
        AuthorityHead, InputReservation,
    };

    fn authority_digest<T: Serialize>(domain: &str, value: &T) -> String {
        let mut h = Sha256::new();
        h.update(domain.as_bytes());
        h.update([0]);
        h.update(serde_json::to_vec(value).unwrap());
        hex::encode(h.finalize())
    }
    fn fixed_binding(f: &DurableFixedCandidateBindingV1) -> String {
        let mut h = Sha256::new();
        h.update(b"wholepact:durable-fixed-proposal:pczt-0.10.0-pre.1:v1\0");
        h.update(f.schema_version.to_le_bytes());
        h.update(f.revision.to_le_bytes());
        h.update(f.expiry_height.to_le_bytes());
        for v in [
            &f.network_profile_id,
            &f.agreement_id,
            &f.obligation_id,
            &f.proposal_id,
            &f.proposal_digest,
            &f.manifest_digest,
            &f.unsigned_artifact_digest,
            &f.proved_artifact_digest,
            &f.effects_commitment,
            &f.policy_digest,
            &f.review_binding,
            &f.action_mapping_digest,
            &f.anchor,
        ] {
            h.update((v.len() as u64).to_le_bytes());
            h.update(v.as_bytes());
        }
        hex::encode(h.finalize())
    }
    struct Fixture {
        journal: SignerConsentJournal,
        session: SignerConsentSession,
        enrollment: AccountEnrollmentRecord,
        manifest: AcceptedManifestRecord,
        request: OwnerControlRequest,
        disclosure: WitnessDisclosureDescriptor,
        owner: String,
        _dir: tempfile::TempDir,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let directory = crate::files::PrivateDirectory::open(dir.path()).unwrap();
            let source = directory
                .signer_journal_source_owner_for_test(&dir.path().join("intent.sqlite"))
                .unwrap();
            let account = "11".repeat(32);
            let journal = SignerConsentJournal::create_encrypted(
                &dir.path().join("intent.sqlite"),
                &wholepact_storage_security::DatabaseKey::from_bytes([131; 32]),
                &account,
                1,
                false,
                &source,
            )
            .unwrap();
            let session = fixture::session(&journal, "synthetic-owner");
            let mut input = crate::consent_journal::tests::proposal(
                "agreement-a",
                "obligation-a",
                "proposal-a",
            )
            .input()
            .clone();
            for p in &mut input.manifest.participants {
                if p.account_id == "account-alice" {
                    p.account_id = account.clone();
                }
            }
            for p in &mut input.manifest.inputs {
                if p.account_id == "account-alice" {
                    p.account_id = account.clone();
                }
            }
            for p in &mut input.manifest.outputs {
                if let wholepact_core::OutputAllocation::Return { account_id, .. } =
                    &mut p.allocation
                {
                    if *account_id == "account-alice" {
                        *account_id = account.clone();
                    }
                }
            }
            let proposal = wholepact_core::Proposal::validate(input).unwrap();
            let disclosure = WitnessDisclosureDescriptor {
                endpoint: "127.0.0.1:443".into(),
                server_name: "synthetic-witness.example".into(),
                witness_id: "synthetic-witness".into(),
                account_id: account.clone(),
                network_profile_id: proposal.manifest().agreement.network_profile_id.clone(),
                policy_digest: "22".repeat(32),
                pinned_server_certificate_digest: "33".repeat(32),
            };
            let owner = "44".repeat(32);
            let genesis = AccountUseGenesis {
                version: 1,
                identity: AccountUseIdentity {
                    account_id: account.clone(),
                    full_viewing_key_digest: "fa".repeat(32),
                    network_profile_id: disclosure.network_profile_id.clone(),
                    derivation_domain: "dedicated-testnet-legacy-zip32-v1".into(),
                },
                witness_id: disclosure.witness_id.clone(),
                witness_origin_digest: account_use_witness_origin_digest(&disclosure).unwrap(),
                owner_certificate_digest: owner.clone(),
                native_birth_digest: "55".repeat(32),
            };
            journal
                .connection
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO signer_account_use_genesis VALUES(1,?1,?2,?3,?4)",
                    params![
                        account,
                        genesis.identity.full_viewing_key_digest,
                        genesis.digest().unwrap(),
                        encode(&genesis).unwrap().as_str()
                    ],
                )
                .unwrap();
            let (enrollment, manifest) = Self::enroll(&journal, &session, &proposal, &genesis);
            let mut fixed = DurableFixedCandidateBindingV1 {
                schema_version: 1,
                network_profile_id: disclosure.network_profile_id.clone(),
                agreement_id: "agreement-a".into(),
                obligation_id: "obligation-a".into(),
                proposal_id: "proposal-a".into(),
                revision: proposal.manifest().agreement.revision,
                expiry_height: 100,
                proposal_digest: proposal.proposal_digest().into(),
                manifest_digest: proposal.manifest_digest().into(),
                unsigned_artifact_digest: "66".repeat(32),
                proved_artifact_digest: "77".repeat(32),
                effects_commitment: "88".repeat(32),
                policy_digest: "99".repeat(32),
                review_binding: "aa".repeat(32),
                action_mapping_digest: "bb".repeat(32),
                anchor: "cc".repeat(32),
                proposal_binding: String::new(),
            };
            fixed.proposal_binding = fixed_binding(&fixed);
            let identity: wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1 =
                serde_json::from_value(serde_json::to_value(&fixed).unwrap()).unwrap();
            let now = now_ms().unwrap();
            let terms = DurablePaymentAdmissionTermsV1 {
                version: 1,
                identity: wholepact_core::manual_enrollment::ManualAccountIdentity {
                    account_id: account.clone(),
                    full_viewing_key_digest: genesis.identity.full_viewing_key_digest.clone(),
                    network_profile_id: genesis.identity.network_profile_id.clone(),
                    derivation_domain: genesis.identity.derivation_domain.clone(),
                },
                original_policy_digest: disclosure.policy_digest.clone(),
                original_genesis_digest: genesis.digest().unwrap(),
                original_birth_commit_digest: "dd".repeat(32),
                original_roster_extension_digest: "ee".repeat(32),
                original_enrollment_ref: "ff".repeat(32),
                writer_certificate_digest: "12".repeat(32),
                authorization_id:
                    crate::authority_bridge::durable_proposal_v1::manual_authorization_id(
                        &identity, &account,
                    )
                    .unwrap(),
                fixed,
                recipient_policy_scope_digest: "23".repeat(32),
                concrete_recipient_scope_digest: "34".repeat(32),
                inputs: vec![InputReservation {
                    input_id: "synthetic-input".into(),
                    nullifier: "45".repeat(32),
                    action_index: 0,
                    value_zatoshis: 1000,
                }],
                maximum_debit_zatoshis: 100,
                fee_share_zatoshis: 10,
                transaction_fee_zatoshis: 20,
                valid_from_ms: now - 1,
                valid_until_ms: now + 60_000,
            };
            let mut request = OwnerControlRequest {
                operation_id: String::new(),
                account_id: account,
                network_profile_id: disclosure.network_profile_id.clone(),
                writer_epoch: 1,
                expected_head: AuthorityHead {
                    sequence: 4,
                    digest: "56".repeat(32),
                },
                control: OwnerControl::AdmitDurablePaymentWithDeliveryV2 {
                    record: Box::new(DurableDeliveryAdmissionRecordV2 {
                        scope: delivery_scope(terms, &manifest, &disclosure),
                        witness_native_review_digest: String::new(),
                    }),
                },
            };
            finish_request(&mut request, &disclosure);
            Self {
                journal,
                session,
                enrollment,
                manifest,
                request,
                disclosure,
                owner,
                _dir: dir,
            }
        }
        fn enroll(
            j: &SignerConsentJournal,
            s: &SignerConsentSession,
            p: &wholepact_core::Proposal,
            g: &AccountUseGenesis,
        ) -> (AccountEnrollmentRecord, AcceptedManifestRecord) {
            let e = j
                .record_enrollment(fixture::approve_enrollment(
                    s,
                    EnrollmentTerms {
                        account_id: g.identity.account_id.clone(),
                        agreement_id: p.manifest().agreement.agreement_id.clone(),
                        participant_id: "alice".into(),
                        principal_id: "synthetic-owner".into(),
                        network_profile_id: g.identity.network_profile_id.clone(),
                        privacy_domain: "synthetic-domain".into(),
                        account_fvk_digest: g.identity.full_viewing_key_digest.clone(),
                        transport: TransportIdentityBinding::RemoteAuthenticatedKeys {
                            transport_identity_id: "synthetic-transport".into(),
                            sender_key_digest: "a1".repeat(32),
                            recipient_key_digest: "b2".repeat(32),
                            channel_binding_digest: "c3".repeat(32),
                        },
                        aggregate_budget_limit_zatoshis: 1_000_000_000,
                        receipt: fixture::receipt(s),
                    },
                ))
                .unwrap();
            let p = s.prepare_manifest(&e, p).unwrap();
            let d = fixture::decision(s, p.review_digest());
            let m = j
                .record_accepted_manifest(s.approve_manifest(p, d).unwrap())
                .unwrap();
            (e, m)
        }
        fn prepared(&self) -> PreparedDurableDeliveryAdmissionIntentV2 {
            self.session
                .prepare_durable_delivery_admission_intent_v2(
                    &self.journal,
                    self.request.clone(),
                    self.disclosure.clone(),
                    &self.owner,
                    self.enrollment.reference(),
                    self.manifest.reference(),
                )
                .unwrap()
        }
        fn approved(&self) -> ApprovedDurableDeliveryAdmissionIntentV2 {
            let p = self.prepared();
            let d = fixture::decision(&self.session, p.digest());
            self.session
                .approve_durable_delivery_admission_intent_v2(p, d)
                .unwrap()
        }
        fn retain(&self) -> RetainedDurableDeliveryAdmissionIntentV2 {
            self.journal
                .retain_durable_delivery_admission_intent_v2(self.approved(), || Ok(()))
                .unwrap()
        }
        fn count(&self) -> u64 {
            self.journal
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM signer_durable_payment_admission_intents",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        }
    }
    fn delivery_scope(
        terms: DurablePaymentAdmissionTermsV1,
        manifest: &AcceptedManifestRecord,
        witness: &WitnessDisclosureDescriptor,
    ) -> DurableDeliveryScopeV2 {
        let mut other = terms.clone();
        other.identity.account_id = "22".repeat(32);
        let identity: wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1 =
            serde_json::from_value(serde_json::to_value(&other.fixed).unwrap()).unwrap();
        let owners = vec![
            DurableDeliveryOwnerLineageV2 {
                account_id: terms.identity.account_id.clone(),
                participant_id: "alice".into(),
                original_authorization_id: terms.authorization_id.clone(),
            },
            DurableDeliveryOwnerLineageV2 {
                account_id: other.identity.account_id.clone(),
                participant_id: "bob".into(),
                original_authorization_id:
                    crate::authority_bridge::durable_proposal_v1::manual_authorization_id(
                        &identity,
                        &other.identity.account_id,
                    )
                    .unwrap(),
            },
        ];
        let material_scopes = owners
            .iter()
            .map(|o| DurableDeliveryMaterialScopeRefV2 {
                account_id: o.account_id.clone(),
                original_scope_digest: "de".repeat(32),
                valid_from_unix_seconds: terms.valid_from_ms / 1000,
                valid_until_unix_seconds: (terms.valid_until_ms + 999) / 1000,
            })
            .collect();
        DurableDeliveryScopeV2 {
        version: 2,
        accepted_manifest_ref: manifest.reference().into(),
        original_writer_epoch: 1,
        delivery: DurableDeliveryPlanV2 {
            dispatcher: DurableDeliveryDispatcherV2 {
                principal_id: "synthetic-host".into(), public_identity_commitment: "a4".repeat(32),
                authentication_profile: DurableDeliveryAuthenticationProfileV2::OriginalProtectedHostDispatcherV2,
                custody_policy_commitment: "a5".repeat(32),
            },
            original_host_generation_binding_digest: "a6".repeat(32),
            original_host_profile_id: "synthetic-host-profile".into(),
            submission_journal_identity: "a7".repeat(32),
            submission_operation_id: "synthetic-submit-operation-v2".into(),
            provider: PreconstructionProvider { source_id: "synthetic-provider".into(), endpoint: "https://provider.example".into(), trust_profile: "single_tls_provider_report_not_consensus".into() },
            route: DurableDeliveryRouteV2::Direct {}, owners,
            valid_from_ms: terms.valid_from_ms, valid_until_ms: terms.valid_until_ms,
            minimum_expiry_margin_blocks: 1, maximum_fresh_admission_lifetime_ms: 1000,
            maximum_explicitly_approved_attempts: 1,
            extraction_rule: DurableDeliveryExtractionRuleV2::FirstDurablyRetainedVerifiedExtraction,
            retry_rule: DurableDeliveryRetryRuleV2::SameRetainedBytesWithFreshAdmission,
            attempt_rule: DurableDeliveryAttemptRuleV2::ExplicitImmediateHostDecision,
        },
        witness: witness.clone(),
        original_ceilings: DurableDeliveryOriginalCeilingsV2 {
            payment_valid_from_ms: terms.valid_from_ms, payment_valid_until_ms: terms.valid_until_ms,
            enrollment_expires_at_ms: terms.valid_until_ms, policy_expires_at_ms: terms.valid_until_ms,
            material_scopes,
        },
        authorization: terms,
        disclosure_rule: DurableDeliveryDisclosureRuleV2::WholeTransactionAndConnectionMetadataToProviderCommitmentsAndLinkageToWitness,
    }
    }
    fn finish_request(r: &mut OwnerControlRequest, d: &WitnessDisclosureDescriptor) {
        let scope = record(r).unwrap().scope.clone();
        r.operation_id = format!(
            "durable-delivery-admit-v2-{}",
            authority_digest(
                "wholepact:durable-delivery-owner-operation:v2",
                &(
                    &scope,
                    &r.account_id,
                    &r.network_profile_id,
                    r.writer_epoch,
                    &r.expected_head
                ),
            )
        );
        let review = authority_digest(
            "wholepact:durable-delivery-witness-native-review:v2",
            &(
                &scope,
                &r.account_id,
                &r.network_profile_id,
                r.writer_epoch,
                &r.expected_head,
                d,
            ),
        );
        if let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &mut r.control {
            record.witness_native_review_digest = review;
        }
        record(r).unwrap().validate_request(r, d).unwrap();
    }
    #[test]
    fn exact_native_pending_approval_is_required_and_retain_is_atomic_before_dispatch() {
        let f = Fixture::new();
        let p = f.prepared();
        let wrong = fixture::decision(&f.session, &"ab".repeat(32));
        assert!(
            f.session
                .approve_durable_delivery_admission_intent_v2(p, wrong)
                .is_err()
        );
        assert_eq!(f.count(), 0);
        let mut calls = 0;
        let outcome = f
            .journal
            .retain_durable_delivery_admission_intent_v2(f.approved(), || {
                calls += 1;
                if calls == 2 {
                    Err(JournalError::Permission)
                } else {
                    Ok(())
                }
            });
        assert!(outcome.is_err());
        assert_eq!(calls, 2);
        assert_eq!(f.count(), 0);
        let retained = f.retain();
        assert_eq!(f.count(), 1);
        assert!(retained.request() == &f.request);
        // No transport is invoked anywhere in this fixture. A crash/return here
        // leaves the full exact intent, without any original release or reservation.
        let c = f.journal.connection.lock().unwrap();
        for t in [
            "signer_original_consents",
            "signer_release_intents",
            "signer_input_reservations",
        ] {
            assert_eq!(
                c.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r
                    .get::<_, u64>(0))
                    .unwrap(),
                0
            );
        }
    }
    #[test]
    fn same_body_retry_keeps_first_receipt_and_changed_head_is_conflict() {
        let mut f = Fixture::new();
        let first = f.retain();
        let retry = f.retain();
        assert!(first == retry);
        assert_eq!(f.count(), 1);
        // The original pristine sequence remains four; only the proposed head changes.
        f.request.expected_head.digest = "67".repeat(32);
        finish_request(&mut f.request, &f.disclosure);
        assert!(matches!(
            f.session.prepare_durable_delivery_admission_intent_v2(
                &f.journal,
                f.request.clone(),
                f.disclosure.clone(),
                &f.owner,
                f.enrollment.reference(),
                f.manifest.reference()
            ),
            Err(JournalError::Conflict)
        ));
        assert_eq!(f.count(), 1);
    }
    #[test]
    fn fresh_native_access_reads_original_manifest_without_rebinding_v2_intent() {
        let mut f = Fixture::new();
        let first = f.retain();
        f.session.invalidate().unwrap();
        f.session = fixture::session(&f.journal, "synthetic-owner");
        assert!(
            f.session
                .prepare_durable_delivery_admission_intent_v2(
                    &f.journal,
                    f.request.clone(),
                    f.disclosure.clone(),
                    &f.owner,
                    f.enrollment.reference(),
                    f.manifest.reference()
                )
                .is_err()
        );
        let proposal = f.manifest.proposal().unwrap();
        let g = account_use_storage::inspect(
            &f.journal.connection.lock().unwrap(),
            &f.request.account_id,
        )
        .unwrap()
        .genesis()
        .unwrap()
        .clone();
        (f.enrollment, f.manifest) = Fixture::enroll(&f.journal, &f.session, &proposal, &g);
        assert_ne!(first.enrollment_ref(), f.enrollment.reference());
        assert!(
            f.session
                .prepare_durable_delivery_admission_intent_v2(
                    &f.journal,
                    f.request.clone(),
                    f.disclosure.clone(),
                    &f.owner,
                    f.enrollment.reference(),
                    f.manifest.reference()
                )
                .is_err()
        );
        let historical = f
            .journal
            .durable_delivery_admission_intent_v2(
                &record(&f.request)
                    .unwrap()
                    .scope
                    .authorization
                    .authorization_id,
                &f.session,
            )
            .unwrap()
            .unwrap();
        assert!(first == historical);
        assert_eq!(f.count(), 1);
    }
    #[test]
    fn historical_row_survives_native_expiry_revocation_and_does_not_create_approval() {
        let f = Fixture::new();
        let first = f.retain();
        fixture::expire_receipt_monotonically(&f.session, first.native_receipt().nonce());
        f.session.invalidate().unwrap();
        let current = fixture::session(&f.journal, "synthetic-owner");
        let read = f
            .journal
            .durable_delivery_admission_intent_v2(
                &record(&f.request)
                    .unwrap()
                    .scope
                    .authorization
                    .authorization_id,
                &current,
            )
            .unwrap()
            .unwrap();
        assert!(read == first);
        assert!(
            f.session
                .prepare_durable_delivery_admission_intent_v2(
                    &f.journal,
                    f.request.clone(),
                    f.disclosure.clone(),
                    &f.owner,
                    f.enrollment.reference(),
                    f.manifest.reference()
                )
                .is_err()
        );
    }
    #[test]
    fn strict_payload_rejects_unknown_duplicate_fields_and_historical_link_substitution() {
        let f = Fixture::new();
        let first = f.retain();
        let raw = encode(&first.0).unwrap();
        let unknown = raw.replacen('{', "{\"unexpected\":1,", 1);
        assert!(decode::<DurableDeliveryAdmissionIntentV2>(unknown).is_err());
        let duplicate = raw.replacen('{', "{\"version\":1,", 1);
        assert!(decode::<DurableDeliveryAdmissionIntentV2>(duplicate).is_err());
        let c = f.journal.connection.lock().unwrap();
        for field in 0..4 {
            let mut changed = first.0.clone();
            match field {
                0 => changed.owner_certificate_digest = "78".repeat(32),
                1 => changed.enrollment_ref = "89".repeat(32),
                2 => changed.manifest_ref = "9a".repeat(32),
                _ => changed.native_receipt.writer_epoch += 1,
            };
            changed.native_review_digest = changed.review_digest().unwrap();
            assert!(validate_original_rows(&c, &changed).is_err());
        }
    }

    #[test]
    fn mixed_historical_reader_preserves_v2_and_v1_financial_projection_refuses() {
        let f = Fixture::new();
        let first = f.retain();
        let c = f.journal.connection.lock().unwrap();
        let mixed = crate::consent_journal::financial_admission_intents::read_all(&c).unwrap();
        assert_eq!(mixed.len(), 1);
        assert!(
            matches!(&mixed[0], crate::consent_journal::financial_admission_intents::HistoricalFinancialAdmissionIntent::V2(value) if value == &first)
        );
        assert!(crate::consent_journal::financial_admission_intents::require_no_v2(&c).is_err());
        assert!(
            crate::consent_journal::durable_payment_admission_intent_v1::read(
                &c,
                &record(&f.request)
                    .unwrap()
                    .scope
                    .authorization
                    .authorization_id
            )
            .is_err()
        );
    }
    #[test]
    fn complete_scope_and_original_manifest_changes_cannot_rewrite_first_intent() {
        let mut f = Fixture::new();
        let first = f.retain();
        if let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &mut f.request.control {
            record.scope.delivery.maximum_explicitly_approved_attempts += 1;
        }
        finish_request(&mut f.request, &f.disclosure);
        assert!(
            f.session
                .prepare_durable_delivery_admission_intent_v2(
                    &f.journal,
                    f.request.clone(),
                    f.disclosure.clone(),
                    &f.owner,
                    f.enrollment.reference(),
                    f.manifest.reference()
                )
                .is_err()
        );
        let c = f.journal.connection.lock().unwrap();
        assert!(
            read(
                &c,
                &record(first.request())
                    .unwrap()
                    .scope
                    .authorization
                    .authorization_id
            )
            .unwrap()
            .as_ref()
                == Some(&first)
        );
        let mut changed = first.0.clone();
        if let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } =
            &mut changed.request.control
        {
            record.scope.accepted_manifest_ref = "ab".repeat(32);
        }
        finish_request(&mut changed.request, &changed.disclosure);
        changed.native_review_digest = changed.review_digest().unwrap();
        assert!(validate_original_rows(&c, &changed).is_err());
    }
    #[cfg(feature = "pending-birth-owner-signing")]
    #[test]
    fn v2_snapshot_rejects_malformed_allowed_outbox_and_preserves_original_intent() {
        let f = Fixture::new();
        let first = f.retain();
        let genesis = account_use_storage::inspect(
            &f.journal.connection.lock().unwrap(),
            &f.request.account_id,
        )
        .unwrap()
        .genesis()
        .unwrap()
        .clone();
        f.journal.check_durable_delivery_entry_v2(&genesis).unwrap();
        {
            let c = f.journal.connection.lock().unwrap();
            c.execute("INSERT INTO signer_durable_construction_outbox(operation_id,request_digest,enrollment_ref,manifest_ref,payload) VALUES(?1,?2,?3,?4,?5)", params![
                "synthetic-corrupt-outbox", "a1".repeat(32), f.enrollment.reference(), f.manifest.reference(), "{}"
            ]).unwrap();
        }
        assert!(f.journal.check_durable_delivery_entry_v2(&genesis).is_err());
        assert_eq!(f.count(), 1);
        let c = f.journal.connection.lock().unwrap();
        assert!(
            read(
                &c,
                &record(first.request())
                    .unwrap()
                    .scope
                    .authorization
                    .authorization_id
            )
            .unwrap()
            .as_ref()
                == Some(&first)
        );
    }
    #[cfg(feature = "pending-birth-owner-signing")]
    #[test]
    fn v2_snapshot_rejects_manifest_index_substitution_under_unchanged_schema() {
        for field in ["proposal_id", "proposal_digest"] {
            let f = Fixture::new();
            let genesis = account_use_storage::inspect(
                &f.journal.connection.lock().unwrap(),
                &f.request.account_id,
            )
            .unwrap()
            .genesis()
            .unwrap()
            .clone();
            f.journal.check_durable_delivery_entry_v2(&genesis).unwrap();
            {
                let c = f.journal.connection.lock().unwrap();
                let trigger: String = c
                    .query_row(
                        "SELECT sql FROM sqlite_schema WHERE name='signer_manifests_no_update'",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                c.execute_batch("DROP TRIGGER signer_manifests_no_update")
                    .unwrap();
                c.execute(
                    &format!("UPDATE signer_accepted_manifests SET {field}=?1 WHERE reference=?2"),
                    params!["ab".repeat(32), f.manifest.reference()],
                )
                .unwrap();
                c.execute_batch(&trigger).unwrap();
            }
            assert!(f.journal.check_durable_delivery_entry_v2(&genesis).is_err());
        }
    }
    #[cfg(feature = "pending-birth-owner-signing")]
    #[test]
    fn v2_snapshot_reads_expired_historical_receipt_but_v1_entry_refuses_v2() {
        let f = Fixture::new();
        let first = f.retain();
        let genesis = account_use_storage::inspect(
            &f.journal.connection.lock().unwrap(),
            &f.request.account_id,
        )
        .unwrap()
        .genesis()
        .unwrap()
        .clone();
        fixture::expire_receipt_monotonically(&f.session, first.native_receipt().nonce());
        f.session.invalidate().unwrap();
        f.journal.check_durable_delivery_entry_v2(&genesis).unwrap();
        assert!(f.journal.check_durable_born_entry_v1(&genesis).is_err());
    }
    #[test]
    fn status_requires_exact_request_scope_original_manifest_and_finite_material_claim() {
        use crate::authority_bridge::durable_delivery_admission_ipc_v2::DurableDeliveryAdmissionStatusV2;
        let f = Fixture::new();
        let retained = f.retain();
        let status = DurableDeliveryAdmissionStatusV2 {
            version: 2,
            request: f.request.clone(),
            scope: record(&f.request).unwrap().scope.clone(),
            original_enrollment_ref: f.enrollment.reference().into(),
            original_accepted_manifest_ref: f.manifest.reference().into(),
            original_local_intent_digest: retained.history_digest().unwrap(),
            authenticated_witness_history_digest: "ac".repeat(32),
            witness_committed: false,
            current_fixed_material_source: "unchecked".into(),
        };
        status.validate().unwrap();
        for change in 0..6 {
            let mut changed = status.clone();
            match change {
                0 => changed.scope.delivery.maximum_explicitly_approved_attempts += 1,
                1 => changed.original_accepted_manifest_ref = "bc".repeat(32),
                2 => changed.current_fixed_material_source = "usable".into(),
                3 => changed.authenticated_witness_history_digest = "not-a-digest".into(),
                4 => changed.request.expected_head.digest = "cd".repeat(32),
                _ => changed.original_local_intent_digest = String::new(),
            }
            assert!(changed.validate().is_err());
        }
    }
}
