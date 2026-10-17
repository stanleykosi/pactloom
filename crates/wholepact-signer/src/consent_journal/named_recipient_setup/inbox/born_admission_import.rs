//! Evidence-only recovery of an exact original born admission. This deliberately
//! creates no Started marker or signature. A previous unconsumed inbox sequence
//! can be retained without requiring the owner to authorize that payment.
use super::born_admission_input::{PreparedBornAdmissionInputV1, prepare_admission_input};
use super::*;
use wholepact_authority::AuthorityClient;

pub(crate) struct PreparedBornAdmissionImportV1 {
    operation: NamedRecipientOperation,
    profile: LiveNamedRecipientProfile,
    original: NamedRecipientOriginalRecordV1,
    input: PreparedBornAdmissionInputV1,
    deadline: Instant,
    digest: String,
    display: String,
}
impl LiveNamedRecipientProfile {
    pub(crate) fn prepare_born_admission_import_v1(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        client: &AuthorityClient,
        authorization_id: &str,
        operation: NamedRecipientOperation,
    ) -> ImportResult<PreparedBornAdmissionImportV1> {
        id(authorization_id).map_err(unavailable)?;
        require_profile_owner(self, journal)?;
        let deadline = operation.deadline();
        let current = || {
            operation.check()?;
            check_setup_current(&self.source, deadline).map_err(unavailable)
        };
        current()?;
        let reference: String = journal.connection.lock().map_err(unavailable)?.query_row(
            "SELECT reference FROM signer_named_recipient_originals WHERE profile_ref=?1 AND authorization_id=?2",
            params![self.record.reference, authorization_id], |r| r.get(0),
        ).map_err(unavailable)?;
        let (_, retained) = load_profile_and_original(journal, self, &reference)?;
        let original = retained.record;
        // No current signing-window check: this can only retain exact historical
        // evidence. Permanent exclusion, current native session and namespace
        // ownership still apply and are checked again in the final transaction.
        require_local_origin(self, &original, journal, session, vault)?;
        current()?;
        let history = client
            .reconcile_history_checked_until(deadline, || {
                current().map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(unavailable)?;
        let input = prepare_admission_input(self, &original, &history, client, deadline, current)?;
        let digest = digest(
            "wholepact:native-born-admission-evidence-import:v1",
            &(
                &self.record.reference,
                &original.reference,
                input.binding_digest()?,
                self.source.entry_digest(),
            ),
        )
        .map_err(unavailable)?;
        let display = format!(
            "RETAIN EXACT ORIGINAL ADMISSION EVIDENCE ONLY\nAccount: {}\nAuthorization: {}\nOriginal: {}\nAuthenticated ciphertext: {}\nReceipt: {}\n\nThis stores the original witness admission ciphertext unchanged in its exact authenticated stream position. It creates no signing consent, Started marker, signature, new authorization, refreshed deadline, refund or payment. Historical expired evidence may be retained; its original limits stay unchanged. A sequence gap is never skipped or reset. This lets you preserve a declined or interrupted original without being forced to sign it.\nNative review: {}",
            self.record.account_id,
            authorization_id,
            original.reference,
            input.envelope_digest(),
            input.binding_digest()?,
            digest,
        );
        current()?;
        Ok(PreparedBornAdmissionImportV1 {
            operation,
            profile: self.clone(),
            original,
            input,
            deadline,
            digest,
            display,
        })
    }
}
impl PreparedBornAdmissionImportV1 {
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn display(&self) -> &str {
        &self.display
    }
    pub(crate) fn approve(
        self,
        decision: NativeDecision,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        client: &AuthorityClient,
    ) -> ImportResult<()> {
        require_profile_owner(&self.profile, journal)?;
        if decision.binding() != &self.profile.source
            || decision.reviewed_digest() != self.digest
            || decision.consumed_at().elapsed() >= Duration::from_secs(120)
        {
            return Err(TransportError::DisclosureDenied);
        }
        let current = || {
            self.operation.check()?;
            check_setup_current(&self.profile.source, self.deadline).map_err(unavailable)
        };
        current()?;
        let history = client
            .reconcile_history_checked_until(self.deadline, || {
                current().map_err(|_| wholepact_authority::AuthorityError::Permission)
            })
            .map_err(unavailable)?;
        let actual = born_original_history::authenticate_admission(
            &self.profile,
            &self.original,
            &history,
            client,
        )?;
        self.input
            .receipt()
            .validate_for(&self.profile.record, &self.original, &actual)
            .map_err(unavailable)?;
        let records = journal
            .acquire_preconstruction_records(
                &self.profile.record.enrollment_ref,
                &self.profile.record.manifest_ref,
                session,
            )
            .map_err(unavailable)?;
        let own = final_signing::retained_own_policy(&self.original, vault)?;
        require_own_context(&self.profile, &self.original, &own, vault, &records)?;
        let origin = self
            .original
            .born_origin
            .as_ref()
            .ok_or(TransportError::WrongContext)?;
        let mut c = journal.connection.lock().map_err(unavailable)?;
        current()?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(unavailable)?;
        let raw: String = tx.query_row(
            "SELECT payload FROM signer_named_recipient_originals WHERE reference=?1 AND profile_ref=?2",
            params![self.original.reference, self.profile.record.reference], |r| r.get(0),
        ).map_err(unavailable)?;
        if decode::<NamedRecipientOriginalRecordV1>(raw).map_err(unavailable)? != self.original {
            return Err(TransportError::WrongContext);
        }
        super::super::super::named_recipient_inventory::read_all(
            &tx,
            &self.profile.record.account_id,
        )
        .map_err(unavailable)?;
        origin
            .require_actual_signer(&tx, &self.profile.record, records.enrollment())
            .map_err(unavailable)?;
        origin
            .checkpoint_receipt
            .require_retained(&tx)
            .map_err(unavailable)?;
        self.input
            .commit_into(&tx, &self.profile, &self.original, &records)?;
        super::super::super::named_recipient_inventory::read_all(
            &tx,
            &self.profile.record.account_id,
        )
        .map_err(unavailable)?;
        storage::bounded(&tx, journal.capacity_limits()).map_err(unavailable)?;
        records.check_current().map_err(unavailable)?;
        current()?;
        let _publication = self
            .profile
            .source
            .publication_lease()
            .map_err(unavailable)?;
        current()?;
        records.check_current().map_err(unavailable)?;
        tx.commit()
            .map_err(|_| TransportError::ImportCommittedButUnavailable)?;
        current().map_err(|_| TransportError::ImportCommittedButUnavailable)
    }
}
fn require_local_origin(
    profile: &LiveNamedRecipientProfile,
    original: &NamedRecipientOriginalRecordV1,
    journal: &SignerConsentJournal,
    session: &SignerConsentSession,
    vault: &AccountVault,
) -> ImportResult<()> {
    let records = journal
        .acquire_preconstruction_records(
            &profile.record.enrollment_ref,
            &profile.record.manifest_ref,
            session,
        )
        .map_err(unavailable)?;
    let own = final_signing::retained_own_policy(original, vault)?;
    require_own_context(profile, original, &own, vault, &records)?;
    let origin = original
        .born_origin
        .as_ref()
        .ok_or(TransportError::WrongContext)?;
    let c = journal.connection.lock().map_err(unavailable)?;
    origin
        .require_actual_signer(&c, &profile.record, records.enrollment())
        .map_err(unavailable)?;
    origin
        .checkpoint_receipt
        .require_retained(&c)
        .map_err(unavailable)?;
    records.check_current().map_err(unavailable)
}
