//! Exact native manual enrollment from an acknowledged ORIGINAL born vault.
//! The durable record is evidence. Only current opaque native/witness owners
//! admit publication; financial/key-release gates deliberately remain separate.
use super::acknowledgement::RetainedBornAccountOrigin;
use super::*;
use crate::{
    consent_journal::{SignerConsentJournal, TransportIdentityBinding},
    ipc::AuthenticatedPeer,
};
use wholepact_authority::manual_enrollment::{
    AuthenticatedBornManualEnrollment, BornManualEnrollmentAdmissionRecord,
    ManualEnrollmentExtension,
};
use wholepact_authority::{
    ReconciledAuthorityHistory, WriterStatus, account_use::AccountUseGenesis,
};
use wholepact_core::manual_enrollment::{
    BornManualEnrollmentTerms, BornManualScope, BornManualSignerBinding, ManualAccountIdentity,
    ManualHostGenerationBinding,
};
use wholepact_storage_security::DatabaseKey;

pub(crate) mod attempts;
pub(super) mod publication;
use publication::{AdmissionAudit, BornManualWitness};
mod continuation;
pub(super) use continuation::validate_acquire_attempt_bytes;
pub(crate) use continuation::{ApprovedBornManualReentry, PreparedBornManualReentry};
pub(super) const ACQUIRE_ATTEMPT: &str = "born-manual-first-acquire.wp";
const INTENT: &str = "born-manual-intent.wp";
const COMMIT: &str = "born-manual-commit.wp";
const MAX_INTENT: usize = 128 * 1024;
const JOURNAL: &str = "authority.sqlite";

/// Complete immutable audit. Deserialization cannot restore native approval,
/// a writer session, the original process association, or financial authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BornManualEnrollmentRecord {
    pub(crate) terms: BornManualEnrollmentTerms,
    pub(crate) terms_digest: String,
    pub(crate) genesis: AccountUseGenesis,
    pub(crate) first_process_binding: TransportIdentityBinding,
    pub(crate) first_native_principal: String,
    pub(crate) signer_native_review_digest: String,
}
impl BornManualEnrollmentRecord {
    pub(crate) fn reference(&self) -> Result<String> {
        self.validate()?;
        canonical("wholepact:born-manual-enrollment-record:v1", self)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.terms.validate().map_err(|_| Error::InvalidData)?;
        self.genesis.validate().map_err(|_| Error::InvalidData)?;
        let t = &self.terms;
        if self.terms_digest != t.terms_digest().map_err(|_| Error::InvalidData)?
            || self.genesis.identity.account_id != t.identity.account_id
            || self.genesis.identity.full_viewing_key_digest != t.identity.full_viewing_key_digest
            || self.genesis.identity.network_profile_id != t.identity.network_profile_id
            || self.genesis.identity.derivation_domain != t.identity.derivation_domain
            || self.genesis.digest().map_err(|_| Error::InvalidData)?
                != t.account_use_genesis_digest
            || self.genesis.witness_origin_digest != t.original_witness_origin_digest
            || self.genesis.native_birth_digest != t.native_birth_digest
            || self.genesis.owner_certificate_digest != t.signer.owner_certificate_digest
            || canonical(
                "wholepact:born-manual-transport:v1",
                &self.first_process_binding,
            )? != t.transport_binding_digest
            || self.first_native_principal.is_empty()
            || self.first_native_principal.len() > 128
            || !is_hash(&self.signer_native_review_digest)
            || self.signer_native_review_digest
                != review_digest(
                    t,
                    &self.genesis,
                    &self.first_process_binding,
                    &self.first_native_principal,
                )?
        {
            return Err(Error::ReviewMismatch);
        }
        match &self.first_process_binding {
            TransportIdentityBinding::LocalProcess {
                account_id,
                agreement_id,
                participant_id,
                pid,
                signer_generation,
                ..
            } if account_id == &t.identity.account_id
                && agreement_id == &t.scope.agreement_id
                && participant_id == &t.scope.participant_id
                && *pid > 0
                && *signer_generation > 0 => {}
            _ => return Err(Error::Authentication),
        }
        Ok(())
    }
    pub(crate) fn extension(&self) -> Result<ManualEnrollmentExtension> {
        Ok(ManualEnrollmentExtension {
            version: 1,
            terms: self.terms.clone(),
            enrollment_ref: self.reference()?,
            enrollment_record_digest: self.reference()?,
            sequence: 1,
            predecessor_digest: None,
        })
    }
}
fn review_digest(
    terms: &BornManualEnrollmentTerms,
    genesis: &AccountUseGenesis,
    process: &TransportIdentityBinding,
    principal: &str,
) -> Result<String> {
    canonical(
        "wholepact:native-born-manual-enrollment-review:v1",
        &(terms, genesis, process, principal),
    )
}
pub(super) fn original(account: &AccountVault) -> Result<&RetainedBornAccountOrigin> {
    let validated = active::ValidatedOriginalAccount::for_account(account)?;
    let origin = validated.origin();
    if account.account.restored
        || account.generation.is_some()
        || account.authority_initialized
        || !account.account.born_authority_pending
        || origin.permanent_exclusion().is_some()
        || account.directory.root().to_str()
            != Some(origin.anchor().intent.original_target.as_str())
    {
        return Err(Error::RecoveryRequired);
    }
    require_canonical_existing_root(account.directory.root())?;
    validated.check_envelope(account)?;
    Ok(origin)
}
fn target_digest(account: &AccountVault) -> Result<String> {
    canonical(
        "wholepact:born-manual-signer-target:v1",
        &account.directory.root(),
    )
}
fn envelope_digest(account: &AccountVault) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        account.directory.read("account.wp", 512 * 1024)?,
    )))
}
fn require_scope(
    scope: &BornManualScope,
    policy: &AccountPolicy,
    account: &AccountVault,
    now: u64,
) -> Result<()> {
    if scope.privacy_domain != account.account.privacy_domain()
        || !policy.agreement_ids.contains(&scope.agreement_id)
        || scope
            .recipient_scope_digests
            .iter()
            .any(|r| !policy.recipient_scope_digests.contains(r))
        || scope.aggregate_budget_zatoshis > policy.aggregate_budget_zatoshis
        || scope.per_operation_limit_zatoshis > policy.per_operation_limit_zatoshis
        || scope.maximum_fee_share_zatoshis > policy.maximum_fee_share_zatoshis
        || scope.maximum_transaction_fee_zatoshis > policy.maximum_transaction_fee_zatoshis
        || scope.maximum_permit_lifetime_ms > policy.maximum_permit_lifetime_ms
        || scope.expires_at_ms > policy.policy_expires_at_ms
        || scope.expires_at_ms <= now
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(())
}
fn now_ms() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidData)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::InvalidData)
}
/// No general path/JSON factory. This owns the actual bound source and first
/// key assignment; the password key itself never enters review/export data.
pub(crate) struct PreparedBornManualEnrollment {
    account: Arc<AccountVault>,
    record: BornManualEnrollmentRecord,
    journal_key: Zeroizing<[u8; 32]>,
    source: NativeAuthorityBinding,
    peer: AuthenticatedPeer,
    display: Zeroizing<String>,
}
impl PreparedBornManualEnrollment {
    pub(crate) fn prepare(
        account: Arc<AccountVault>,
        host: ManualHostGenerationBinding,
        scope: BornManualScope,
        operation_id: String,
        pairing: &crate::native_ui::AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        pairing.check_current()?;
        if pairing.native_origin() != &owner.native().binding() {
            return Err(Error::Authentication);
        }
        inventory(&account.directory)?;
        if account.directory.exists(INTENT)?
            || account.directory.exists(COMMIT)?
            || account.directory.exists(JOURNAL)?
        {
            return Err(Error::RecoveryRequired);
        }
        let origin = original(&account)?;
        let request = origin.original_request();
        let now = now_ms()?;
        require_scope(&scope, &request.policy, &account, now)?;
        if pairing.account_id() != account.account_id()?
            || pairing.agreement_id() != scope.agreement_id
            || pairing.participant_id() != scope.participant_id
        {
            return Err(Error::ReviewMismatch);
        }
        let process = pairing.binding().clone();
        let terms = BornManualEnrollmentTerms {
            version: 1,
            operation_id,
            identity: ManualAccountIdentity {
                account_id: account.account_id()?,
                full_viewing_key_digest: origin
                    .anchor()
                    .identity()
                    .full_viewing_key_digest()
                    .into(),
                network_profile_id: origin.anchor().identity().network_profile_id().into(),
                derivation_domain: origin.anchor().identity().derivation_domain().into(),
            },
            birth_request_digest: request.digest().map_err(|_| Error::InvalidData)?,
            birth_commit_digest:
                wholepact_authority::manual_enrollment::original_birth_commit_digest(
                    origin.witness_commit(),
                )
                .map_err(|_| Error::InvalidData)?,
            native_birth_digest: origin.anchor().birth_digest().into(),
            original_policy_digest: request.disclosure.policy_digest.clone(),
            account_use_genesis_digest: origin
                .anchor()
                .expected_account_use_genesis()?
                .digest()
                .map_err(|_| Error::InvalidData)?,
            original_witness_origin_digest: origin.anchor().witness_origin().digest()?,
            host,
            signer: BornManualSignerBinding {
                enrollment_generation_id: hex::encode(vault::random::<32>()?),
                signer_target_digest: target_digest(&account)?,
                original_envelope_digest: envelope_digest(&account)?,
                owner_certificate_digest: request.policy.owner_certificate_digest.clone(),
                writer_certificate_digest: request.policy.initial_writer_certificate_digest.clone(),
                writer_epoch: request.policy.initial_writer_epoch,
                native_signer_measurement: owner.native().measurement().into(),
            },
            scope,
            transport_binding_digest: canonical("wholepact:born-manual-transport:v1", &process)?,
            issued_at_ms: now,
        };
        terms.validate().map_err(|_| Error::InvalidData)?;
        let genesis = origin.anchor().expected_account_use_genesis()?;
        let principal = owner.native().principal_id().to_owned();
        let digest = review_digest(&terms, &genesis, &process, &principal)?;
        let record = BornManualEnrollmentRecord {
            terms_digest: terms.terms_digest().map_err(|_| Error::InvalidData)?,
            terms,
            genesis,
            first_process_binding: process,
            first_native_principal: principal,
            signer_native_review_digest: digest,
        };
        record.validate()?;
        let display = Zeroizing::new(format!(
            "RETAIN EXACT ORIGINAL-ACCOUNT MANUAL ENROLLMENT INTENT\n\nSigner target: {}\n\n{}\n\nThe host generation/profile/inventory below are the paired process's exact claims, reviewed by you; this signer cannot authenticate the host's encrypted databases remotely. Final host admission must independently match the actual locked generation and inherited account/FVK identities. This creates only an immutable local intent and a new independently assigned encrypted journal key. It neither creates a journal nor changes original policy references. The separate independent witness owner must review a versioned extension adding this exact record reference under unchanged account-wide constraints. Existing exposure, exclusions and lifetime charges are never reset. No spend key is released, no transaction is signed, and no restored or retired account is eligible.\n\nExact native review: {}",
            account.directory.root().display(),
            serde_json::to_string_pretty(&record).map_err(|_| Error::InvalidData)?,
            record.signer_native_review_digest
        ));
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        pairing.check_current()?;
        Ok(Self {
            account,
            record,
            journal_key: Zeroizing::new(vault::random::<32>()?),
            source: owner.native().binding(),
            peer: pairing.current_peer(),
            display,
        })
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.record.signer_native_review_digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.source.check_current()?;
        self.peer.check_current()?;
        Ok(self.display.to_string())
    }
    pub(crate) fn approve_and_retain(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<RetainedBornManualEnrollment> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        self.source.check_current()?;
        self.peer.check_current()?;
        if decision.binding() != &self.source
            || owner.native().binding() != self.source
            || decision.reviewed_digest() != self.reviewed_digest()
        {
            return Err(Error::ReviewMismatch);
        }
        let _lease = self.source.publication_lease()?;
        check_record_source(&self.account, &self.record)?;
        if self.account.directory.exists(INTENT)?
            || self.account.directory.exists(JOURNAL)?
            || self.account.directory.exists(COMMIT)?
        {
            return Err(Error::RecoveryRequired);
        }
        let mut plain = Zeroizing::new(vec![1]);
        plain.extend(self.journal_key.iter());
        plain.extend(serde_json::to_vec(&self.record).map_err(|_| Error::InvalidData)?);
        let encrypted = vault::encrypt(
            &self.account.encryption_key,
            &intent_domain(&self.account)?,
            &plain,
        )?;
        self.account.directory.write(INTENT, &encrypted)?;
        self.account.directory.sync_all_files()?;
        read_retained(self.account.clone())
    }
}
fn intent_domain(account: &AccountVault) -> Result<Vec<u8>> {
    let mut d = b"wholepact:born-manual-enrollment-intent:v1\0".to_vec();
    d.extend(original(account)?.anchor().birth_digest().as_bytes());
    Ok(d)
}
fn check_record_source(account: &AccountVault, record: &BornManualEnrollmentRecord) -> Result<()> {
    record.validate()?;
    inventory(&account.directory)?;
    let origin = original(account)?;
    let request = origin.original_request();
    let terms = &record.terms;
    if terms.signer.signer_target_digest != target_digest(account)?
        || terms.signer.original_envelope_digest != envelope_digest(account)?
        || terms.identity.account_id != account.account_id()?
        || record.genesis != origin.anchor().expected_account_use_genesis()?
        || terms.birth_request_digest != request.digest().map_err(|_| Error::InvalidData)?
        || terms.birth_commit_digest
            != wholepact_authority::manual_enrollment::original_birth_commit_digest(
                origin.witness_commit(),
            )
            .map_err(|_| Error::InvalidData)?
        || terms.native_birth_digest != origin.anchor().birth_digest()
        || terms.original_policy_digest != request.disclosure.policy_digest
        || terms.signer.owner_certificate_digest != request.policy.owner_certificate_digest
        || terms.signer.writer_certificate_digest
            != request.policy.initial_writer_certificate_digest
        || terms.signer.writer_epoch != request.policy.initial_writer_epoch
    {
        return Err(Error::ReviewMismatch);
    }
    if account.directory.exists(ACQUIRE_ATTEMPT)? {
        let intent = account.directory.read(INTENT, MAX_INTENT)?;
        validate_acquire_attempt_bytes(
            record,
            &hex::encode(Sha256::digest(&intent)),
            &account.encryption_key,
            &account.directory.read(ACQUIRE_ATTEMPT, MAX_INTENT)?,
        )?;
    }
    let attempt_files = attempts::read_files(&account.directory)?;
    if !attempt_files.is_empty() {
        attempts::validate_files(
            record,
            &hex::encode(Sha256::digest(account.directory.read(INTENT, MAX_INTENT)?)),
            &account.encryption_key,
            &account.directory.read(ACQUIRE_ATTEMPT, MAX_INTENT)?,
            &attempt_files,
        )?;
    }
    // At-rest expiry remains historical; fresh publication checks wall time separately.
    require_scope(&terms.scope, &request.policy, account, terms.issued_at_ms)
}
pub(crate) struct RetainedBornManualEnrollment {
    pub(super) account: Arc<AccountVault>,
    pub(super) record: BornManualEnrollmentRecord,
    pub(super) journal_key: Zeroizing<[u8; 32]>,
    pub(super) intent_digest: String,
}
pub(super) fn read_retained(account: Arc<AccountVault>) -> Result<RetainedBornManualEnrollment> {
    let encrypted = account.directory.read(INTENT, MAX_INTENT)?;
    let plain = vault::decrypt(
        &account.encryption_key,
        &intent_domain(&account)?,
        &encrypted,
    )?;
    if plain.len() < 33 || plain[0] != 1 {
        return Err(Error::InvalidData);
    }
    let record: BornManualEnrollmentRecord =
        serde_json::from_slice(&plain[33..]).map_err(|_| Error::InvalidData)?;
    check_record_source(&account, &record)?;
    let intent_digest = hex::encode(Sha256::digest(&encrypted));
    Ok(RetainedBornManualEnrollment {
        account,
        record,
        journal_key: Zeroizing::new(plain[1..33].try_into().map_err(|_| Error::InvalidData)?),
        intent_digest,
    })
}
impl RetainedBornManualEnrollment {
    pub(crate) fn first_acquire_attempted(&self) -> Result<bool> {
        self.check()?;
        self.account.directory.exists(ACQUIRE_ATTEMPT)
    }
    pub(crate) fn require_preacquire_reentry(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        self.check_current_source(owner)?;
        continuation::require_unattempted_inventory(&self.account.directory)
    }

    pub(crate) fn reopen_exact(&self, owner: &PendingAccountNativeAuthority) -> Result<Self> {
        self.check_current_source(owner)?;
        let next = read_retained(self.account.clone())?;
        if next.record != self.record || next.intent_digest != self.intent_digest {
            return Err(Error::ReviewMismatch);
        }
        Ok(next)
    }

    pub(crate) fn disclosure(&self) -> Result<wholepact_authority::WitnessDisclosureDescriptor> {
        self.check()?;
        Ok(original(&self.account)?
            .original_request()
            .disclosure
            .clone())
    }

    pub(crate) fn check_current_source(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        self.check()?;
        owner.check_current()
    }

    pub(crate) fn record(&self) -> &BornManualEnrollmentRecord {
        &self.record
    }
    pub(crate) fn audit_json(&self, owner: &PendingAccountNativeAuthority) -> Result<String> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        self.check()?;
        let text = serde_json::to_string_pretty(&self.record).map_err(|_| Error::InvalidData)?;
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        Ok(text)
    }
    fn check(&self) -> Result<()> {
        check_record_source(&self.account, &self.record)?;
        if hex::encode(Sha256::digest(
            self.account.directory.read(INTENT, MAX_INTENT)?,
        )) != self.intent_digest
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(crate) fn prepare_publication(
        self,
        history: ReconciledAuthorityHistory,
        witness: AuthenticatedBornManualEnrollment,
        pairing: &crate::native_ui::AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PreparedBornManualPublication> {
        self.prepare_publication_inner(
            history,
            BornManualWitness::First(Box::new(witness)),
            pairing,
            owner,
        )
    }
    fn prepare_publication_inner(
        self,
        history: ReconciledAuthorityHistory,
        witness: BornManualWitness,
        pairing: &crate::native_ui::AuthenticatedPairing,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PreparedBornManualPublication> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        pairing.check_current()?;
        self.check()?;
        witness.check_current().map_err(|_| Error::ReviewMismatch)?;
        if pairing.native_origin() != &owner.native().binding()
            || pairing.account_id() != self.record.terms.identity.account_id
            || pairing.agreement_id() != self.record.terms.scope.agreement_id
            || pairing.participant_id() != self.record.terms.scope.participant_id
        {
            return Err(Error::Authentication);
        }
        check_current_history(&self, &history, &witness)?;
        let digest = canonical(
            if matches!(&witness, BornManualWitness::Continued(_)) {
                "wholepact:native-born-manual-publication:v2"
            } else {
                "wholepact:native-born-manual-publication:v1"
            },
            &(
                &self.record,
                witness.audit(),
                witness.extension(),
                witness.snapshot(),
                witness.session(),
                pairing.binding(),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )?;
        let mut display = Zeroizing::new(format!(
            "CREATE OR FINISH ONE EXACT SIGNER JOURNAL\n\nOriginal native-born identity, original owner/policy and reviewed host target remain unchanged. The independently committed manual extension and current writer below admit only this exact local journal publication. This approval does not authorize spending, offline operation, automation or restoration. Subsequent actions require their own actual native/host/witness gates. Cancel or blur stops new admission; an already admitted local filesystem commit may finish and must be inspected.\n\nStable signer enrollment:\n{}\n\nIndependent extension:\n{}\n\nCurrent writer/head:\n{}\n{}\n\nExact review: {}",
            serde_json::to_string_pretty(&self.record).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(witness.extension()).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(witness.snapshot()).map_err(|_| Error::InvalidData)?,
            serde_json::to_string_pretty(witness.session()).map_err(|_| Error::InvalidData)?,
            digest
        ));
        display.push_str(&format!(
            "\nExact admitted attempt evidence:\n{}",
            serde_json::to_string_pretty(&witness.audit()).map_err(|_| Error::InvalidData)?
        ));
        Ok(PreparedBornManualPublication {
            retained: self,
            history,
            witness,
            source: owner.native().binding(),
            peer: pairing.current_peer(),
            digest,
            display,
        })
    }
}
fn check_current_history(
    retained: &RetainedBornManualEnrollment,
    history: &ReconciledAuthorityHistory,
    witness: &BornManualWitness,
) -> Result<()> {
    let origin = original(&retained.account)?;
    let audit = origin.anchor().audit_historical_witness_link(history)?;
    history
        .require_legacy_online_only()
        .map_err(|_| Error::Unavailable)?;
    let s = history.snapshot();
    let t = &retained.record.terms;
    if history
        .manual_enrollment_extension(&retained.record.reference()?)
        .map_err(|_| Error::Authentication)?
        != Some(witness.extension())
        || history.pending_birth_commit() != Some(origin.witness_commit())
        || audit.permanent_exclusion().is_some()
        || witness.extension() != &retained.record.extension()?
        || witness.snapshot() != s
        || s.writer_status != WriterStatus::Active
        || s.writer_epoch != t.signer.writer_epoch
        || s.writer_certificate_digest != t.signer.writer_certificate_digest
        || s.active_writer_session.as_ref() != Some(witness.session())
        || s.outstanding_reservations != 0
        || s.outstanding_debit_zatoshis != 0
        || s.settled_debit_zatoshis != 0
        || !history
            .permits()
            .map_err(|_| Error::Unavailable)?
            .is_empty()
        || !history.automatic_key_use_admissions().is_empty()
        || !history.recovery_fences().is_empty()
        || now_ms()? >= t.scope.expires_at_ms
    {
        return Err(Error::RecoveryRequired);
    }
    witness.check_current().map_err(|_| Error::ReviewMismatch)
}
pub(crate) struct PreparedBornManualPublication {
    retained: RetainedBornManualEnrollment,
    history: ReconciledAuthorityHistory,
    witness: BornManualWitness,
    source: NativeAuthorityBinding,
    peer: AuthenticatedPeer,
    digest: String,
    display: Zeroizing<String>,
}
impl PreparedBornManualPublication {
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        self.check()?;
        Ok(self.display.to_string())
    }
    fn check(&self) -> Result<()> {
        self.source.check_current()?;
        self.peer.check_current()?;
        self.retained.check()?;
        check_current_history(&self.retained, &self.history, &self.witness)
    }
    pub(crate) fn approve_and_publish(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<BornManualEnrolledSigner> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        self.check()?;
        if owner.native().binding() != self.source
            || decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
        {
            return Err(Error::ReviewMismatch);
        }
        let lease = self.source.publication_lease()?;
        let publication = BornEnrollmentPublication {
            prepared: &self,
            _native: lease,
        };
        self.witness.retain_actual(&self.retained)?;
        let journal = SignerConsentJournal::publish_born_enrollment(&publication)?;
        let complete = BornManualCommit {
            version: self.witness.audit().version(),
            enrollment_ref: self.retained.record.reference()?,
            intent_digest: self.retained.intent_digest.clone(),
            extension: self.witness.extension().clone(),
            admission: self.witness.audit(),
            original_writer_epoch: self.retained.record.terms.signer.writer_epoch,
        };
        let bytes = serde_json::to_vec(&complete).map_err(|_| Error::InvalidData)?;
        if self.retained.account.directory.exists(COMMIT)? {
            let original = read_commit(&self.retained)?;
            if original.enrollment_ref != complete.enrollment_ref
                || original.intent_digest != complete.intent_digest
                || original.extension != complete.extension
                || original.original_writer_epoch != complete.original_writer_epoch
            {
                return Err(Error::ReviewMismatch);
            }
        } else {
            let encrypted = vault::encrypt(
                &self.retained.account.encryption_key,
                &commit_domain(&self.retained)?,
                &bytes,
            )?;
            self.retained.account.directory.write(COMMIT, &encrypted)?;
        }
        self.retained.account.directory.sync_all_files()?;
        self.witness
            .require_retained(&self.retained, &read_commit(&self.retained)?)?;
        drop(publication);
        Ok(BornManualEnrolledSigner {
            retained: self.retained,
            journal: Arc::new(journal),
            source: self.source,
            peer: self.peer,
            witness: self.witness,
            history: self.history,
        })
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BornManualCommit {
    version: u16,
    enrollment_ref: String,
    intent_digest: String,
    extension: ManualEnrollmentExtension,
    admission: AdmissionAudit,
    original_writer_epoch: u64,
}
fn commit_domain(retained: &RetainedBornManualEnrollment) -> Result<Vec<u8>> {
    let mut d = b"wholepact:born-manual-enrollment-commit:v1\0".to_vec();
    d.extend(retained.record.reference()?.as_bytes());
    Ok(d)
}
pub(super) fn read_commit(retained: &RetainedBornManualEnrollment) -> Result<BornManualCommit> {
    let bytes = retained.account.directory.read(COMMIT, MAX_INTENT)?;
    let plain = vault::decrypt(
        &retained.account.encryption_key,
        &commit_domain(retained)?,
        &bytes,
    )?;
    let record: BornManualCommit =
        serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
    if record.version != record.admission.version()
        || record.enrollment_ref != retained.record.reference()?
        || record.intent_digest != retained.intent_digest
        || record.extension != retained.record.extension()?
        || record.original_writer_epoch != retained.record.terms.signer.writer_epoch
    {
        return Err(Error::Authentication);
    }
    record
        .admission
        .validate(&record.extension)
        .map_err(|_| Error::Authentication)?;
    record
        .admission
        .require_attempt_history(&attempts::load(retained)?)?;
    validate_acquire_attempt_bytes(
        &retained.record,
        &retained.intent_digest,
        &retained.account.encryption_key,
        &retained
            .account
            .directory
            .read(ACQUIRE_ATTEMPT, MAX_INTENT)?,
    )?;
    Ok(record)
}
/// Constructor is PRIVATE and borrows the actual one-shot native publication
/// lease plus finite authenticated witness proof. No data-to-token conversion.
pub(crate) struct BornEnrollmentPublication<'a> {
    prepared: &'a PreparedBornManualPublication,
    _native: crate::native_ui::NativePublicationLease<'a>,
}
impl BornEnrollmentPublication<'_> {
    pub(crate) fn check_current(&self) -> Result<()> {
        self.prepared.check()
    }
    pub(crate) fn journal_path(&self) -> PathBuf {
        self.prepared
            .retained
            .account
            .directory
            .root()
            .join(JOURNAL)
    }
    pub(crate) fn journal_key(&self) -> DatabaseKey {
        DatabaseKey::from_bytes(*self.prepared.retained.journal_key)
    }
    pub(crate) fn genesis(&self) -> &AccountUseGenesis {
        &self.prepared.retained.record.genesis
    }
    pub(crate) fn writer_epoch(&self) -> u64 {
        self.prepared.retained.record.terms.signer.writer_epoch
    }
    pub(crate) fn intent_digest(&self) -> &str {
        &self.prepared.retained.intent_digest
    }
}
/// Retains the actual source/journal/peer and bounded publication observation.
/// It deliberately exposes no account/SpendingKey conversion or generic session.
pub(crate) struct BornManualEnrolledSigner {
    retained: RetainedBornManualEnrollment,
    journal: Arc<SignerConsentJournal>,
    source: NativeAuthorityBinding,
    peer: AuthenticatedPeer,
    witness: BornManualWitness,
    history: ReconciledAuthorityHistory,
}
impl BornManualEnrolledSigner {
    pub(crate) fn record(&self) -> &BornManualEnrollmentRecord {
        &self.retained.record
    }
    pub(crate) fn check_current_publication(&self) -> Result<()> {
        self.source.check_current()?;
        self.peer.check_current()?;
        self.retained.check()?;
        let complete = read_commit(&self.retained)?;
        self.witness.require_retained(&self.retained, &complete)?;
        self.journal.check_initial_born_owner(
            &self.retained.record.genesis,
            self.retained.record.terms.signer.writer_epoch,
        )?;
        check_current_history(&self.retained, &self.history, &self.witness)?;
        self.witness
            .check_current()
            .map_err(|_| Error::ReviewMismatch)
    }
    pub(crate) fn require_host_owner(
        &self,
        peer: &AuthenticatedPeer,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        self.check_current_publication()?;
        peer.check_current()?;
        if self.source != owner.native().binding()
            || peer.native_origin != self.source
            || peer.grant_id != self.peer.grant_id
            || peer.scope != self.peer.scope
        {
            return Err(Error::Authentication);
        }
        peer.peer.same_live_process(&self.peer.peer)?;
        Ok(())
    }
    /// Data projection from actual held opaque producers. It cannot restore a
    /// proof from imported JSON and is never accepted as source authority.
    pub(crate) fn host_enrollment_evidence(
        &self,
        request: &wholepact_signer_origin::manual::HostManualEnrollmentRequest,
        peer: &AuthenticatedPeer,
        owner: &PendingAccountNativeAuthority,
        reviewed_digest: &str,
    ) -> Result<wholepact_signer_origin::manual::ManualEnrollmentEvidence> {
        use wholepact_signer_origin::manual::{
            DurableManualEnrollmentAdmission, ManualCurrentState, ManualEnrollmentEvidence,
        };
        self.require_host_owner(peer, owner)?;
        request.validate().map_err(|_| Error::InvalidData)?;
        if request.terms != self.retained.record.terms || !is_hash(reviewed_digest) {
            return Err(Error::ReviewMismatch);
        }
        let committed = read_commit(&self.retained)?;
        let BornManualWitness::First(witness) = &self.witness else {
            return Err(Error::Unavailable);
        };
        let AdmissionAudit::First(admitted) = &committed.admission else {
            return Err(Error::Unavailable);
        };
        if admitted.as_ref() != witness.record() {
            return Err(Error::Authentication);
        }
        let extension = self.witness.extension();
        let audit = original(&self.retained.account)?
            .anchor()
            .audit_historical_witness_link(&self.history)?;
        let checkpoint = canonical(
            "wholepact:born-manual-exclusion-checkpoint:v1",
            audit.checkpoint(),
        )?;
        let snapshot = self.history.snapshot();
        let session = self.witness.session();
        let evidence = ManualEnrollmentEvidence {
            request: request.clone(),
            enrollment_ref: self.retained.record.reference()?,
            witness_extension_digest: extension.digest().map_err(|_| Error::InvalidData)?,
            witness_extension_sequence: extension.sequence,
            witness_extension_predecessor_digest: extension.predecessor_digest.clone(),
            admission: DurableManualEnrollmentAdmission {
                exact_request_digest: request.digest().map_err(|_| Error::InvalidData)?,
                signer_intent_digest: self.retained.intent_digest.clone(),
                witness_admission_digest: admitted
                    .digest_for(extension)
                    .map_err(|_| Error::InvalidData)?,
                admitted_at_ms: admitted.admitted_at_ms,
                admission_deadline_ms: admitted.publication_expires_at_ms,
            },
            current: ManualCurrentState {
                writer_certificate_digest: session.writer_certificate_digest.clone(),
                writer_epoch: snapshot.writer_epoch,
                writer_session_digest: canonical(
                    "wholepact:born-manual-writer-session:v1",
                    session,
                )?,
                writer_session_expires_at_ms: session.expires_at_ms,
                witness_head_sequence: snapshot.head.sequence,
                witness_head_digest: snapshot.head.digest.clone(),
                complete_history_digest: self
                    .history
                    .history_digest()
                    .map_err(|_| Error::InvalidData)?,
                exclusion_checkpoint_digest: checkpoint,
                native_review_digest: reviewed_digest.into(),
            },
        };
        evidence.validate().map_err(|_| Error::InvalidData)?;
        self.require_host_owner(peer, owner)?;
        Ok(evidence)
    }
}
impl AccountVault {
    pub(crate) fn unlock_born_for_manual_enrollment(
        root: &Path,
        password: &[u8],
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Self> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        require_canonical_existing_root(root)?;
        let directory = PrivateDirectory::open_existing(root)?;
        let encrypted = directory.read("account.wp", 512 * 1024)?;
        let opened = active::open_for_manual_enrollment(directory, password, &encrypted)?;
        original(&opened)?;
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        Ok(opened)
    }
    pub(crate) fn retained_born_manual_enrollment(
        self: &Arc<Self>,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<Option<RetainedBornManualEnrollment>> {
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        original(self)?;
        inventory(&self.directory)?;
        if !self.directory.exists(INTENT)? {
            return Ok(None);
        }
        let retained = read_retained(self.clone())?;
        owner.check_current()?;
        owner.native().binding().bounded_deadline()?;
        Ok(Some(retained))
    }
}
/// Exact expanded inventory. Unknown files, partial stages, missing intent or
/// commit-without-journal are preserved and rejected, never repaired/adopted.
pub(super) fn inventory(directory: &PrivateDirectory) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mut names = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(directory.root())? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::InvalidData)?;
        let m = std::fs::symlink_metadata(entry.path())?;
        if !matches!(
            name.as_str(),
            "signer.lock"
                | "account.wp"
                | "birth-owner-request.wp"
                | INTENT
                | COMMIT
                | ACQUIRE_ATTEMPT
                | JOURNAL
                | "authority.sqlite-wal"
                | "authority.sqlite-shm"
                | "authority.sqlite-journal"
        ) && attempts::parse_name(&name).is_none()
            || !m.is_file()
            || m.nlink() != 1
            || m.mode() & 0o077 != 0
            || m.uid() != unsafe { libc::geteuid() }
            || m.len() > 128 * 1024 * 1024
        {
            return Err(Error::InvalidData);
        }
        names.insert(name);
    }
    attempts::check_names(&names)?;
    for name in ["signer.lock", "account.wp", "birth-owner-request.wp"] {
        if !names.contains(name) {
            return Err(Error::RecoveryRequired);
        }
    }
    if (names.contains(JOURNAL) || names.contains(COMMIT) || names.contains(ACQUIRE_ATTEMPT))
        && !names.contains(INTENT)
        || (names.contains(JOURNAL) || names.contains(COMMIT)) && !names.contains(ACQUIRE_ATTEMPT)
        || names.contains(COMMIT) && !names.contains(JOURNAL)
        || names
            .iter()
            .any(|name| name.starts_with("authority.sqlite-") && !names.contains(JOURNAL))
    {
        return Err(Error::RecoveryRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn journal_without_authenticated_intent_is_denied_without_changes() {
        let temp = tempfile::tempdir().unwrap();
        let dir = PrivateDirectory::create(&temp.path().join("source")).unwrap();
        for n in ["account.wp", "birth-owner-request.wp", "authority.sqlite"] {
            dir.write(n, b"synthetic inventory-only bytes").unwrap();
        }
        assert!(inventory(&dir).is_err());
        assert!(!dir.root().join(INTENT).exists());
        assert_eq!(
            dir.read("authority.sqlite", 128).unwrap(),
            b"synthetic inventory-only bytes"
        );
    }
    #[test]
    fn unknown_or_staged_file_cannot_enter_enrollment_inventory() {
        let temp = tempfile::tempdir().unwrap();
        let dir = PrivateDirectory::create(&temp.path().join("source")).unwrap();
        for n in ["account.wp", "birth-owner-request.wp"] {
            dir.write(n, b"synthetic data").unwrap();
        }
        assert!(inventory(&dir).is_ok());
        dir.write("tmp-unreviewed", b"keep").unwrap();
        assert!(inventory(&dir).is_err());
        assert_eq!(dir.read("tmp-unreviewed", 32).unwrap(), b"keep");
    }
}

// Actual typed source; IPC/UI routing remains a separate purpose-specific hook.
pub(crate) mod inventory;

impl RetainedBornManualEnrollment {
    pub(crate) fn original_recipient_policy_export_v2(
        &self,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<super::recipient_policy_v2::OriginalRecipientPolicyExportV2> {
        self.check_current_source(owner)?;
        let data = super::recipient_policy_v2::OriginalRecipientPolicyExportV2::from_retained(
            original(&self.account)?,
        )?;
        self.check_current_source(owner)?;
        Ok(data)
    }
}

pub(crate) mod roster_v2;
