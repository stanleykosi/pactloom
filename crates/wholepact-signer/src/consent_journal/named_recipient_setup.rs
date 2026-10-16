//! Genuine native setup and exact retry in the existing encrypted authority DB.
//! A profile installs explicitly reviewed pins; it never admits a reservation.
use super::named_recipient_records::NamedRecipientProfileRecordV1;
use super::*;
use crate::{
    account::AccountVault,
    native_ui::{NativeAuthority, NativeAuthorityBinding, NativeDecision},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use wholepact_transport::{TransportPublicKey, TransportSecret};

/// Local UI input only. No parsing path turns these pins into trust or authority.
pub(crate) struct NamedRecipientPins {
    pub(crate) verifier_signing: [u8; 32],
    pub(crate) verifier_transport: [u8; 32],
    pub(crate) witness_transport: [u8; 32],
    pub(crate) witness_certificate_digest: String,
    pub(crate) return_transport: [u8; 32],
}
pub(crate) struct PreparedNamedRecipientSetup {
    record: NamedRecipientProfileRecordV1,
    journal: SignerJournalBinding,
    source: NativeAuthorityBinding,
    created: Instant,
    digest: String,
    display: String,
    #[cfg(all(test, feature = "synthetic-qualification"))]
    before_commit: Option<Box<dyn FnOnce() + Send>>,
    #[cfg(all(test, feature = "synthetic-qualification"))]
    after_commit: Option<Box<dyn FnOnce() + Send>>,
}
/// Retained data with a current genuine native/session association. This is not
/// a signing permit, final consent, witness admission or recovery activation.
#[derive(Clone)]
pub(crate) struct LiveNamedRecipientProfile {
    record: NamedRecipientProfileRecordV1,
    journal: SignerJournalBinding,
    source: NativeAuthorityBinding,
}
impl PreparedNamedRecipientSetup {
    /// Reopen only the immutable original profile; fresh acceptance receipts
    /// are not substitutes for its retained enrollment and manifest references.
    pub(crate) fn reopen(
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        native: &NativeAuthority,
        original_profile_ref: &str,
    ) -> crate::Result<Self> {
        Self::reopen_exact(journal, session, vault, native, original_profile_ref, false)
    }
    /// The commitment is shown before retention, so it also recovers a commit
    /// whose generated profile reference was never delivered to the caller.
    pub(crate) fn reopen_by_setup_commitment(
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        native: &NativeAuthority,
        original_setup_digest: &str,
    ) -> crate::Result<Self> {
        Self::reopen_exact(journal, session, vault, native, original_setup_digest, true)
    }
    fn reopen_exact(
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        native: &NativeAuthority,
        lookup: &str,
        by_setup: bool,
    ) -> crate::Result<Self> {
        hash(lookup).map_err(|_| crate::Error::InvalidData)?;
        native.check_current()?;
        let source = native.binding();
        let record = {
            let account = journal
                .account_state()
                .map_err(crate::Error::ConsentJournal)?;
            if account.recovery_required || vault.account().recovery_required() {
                return Err(crate::Error::Locked);
            }
            let permission = session
                .read_lease(&journal.binding(), &account)
                .map_err(|_| crate::Error::Locked)?;
            permission
                .require_native_origin(&source)
                .map_err(|_| crate::Error::Locked)?;
            let _fence = journal
                .authority_fence
                .read()
                .map_err(|_| crate::Error::Locked)?;
            let c = journal
                .connection
                .lock()
                .map_err(|_| crate::Error::Locked)?;
            storage::check_account(&c, &account).map_err(crate::Error::ConsentJournal)?;
            let raw: String = c
                .query_row(
                    if by_setup {
                        "SELECT payload FROM signer_named_recipient_profiles WHERE original_setup_digest=?1"
                    } else {
                        "SELECT payload FROM signer_named_recipient_profiles WHERE reference=?1"
                    },
                    [lookup],
                    |r| r.get(0),
                )
                .map_err(|_| crate::Error::InvalidData)?;
            let raw = Zeroizing::new(raw);
            let record: NamedRecipientProfileRecordV1 =
                serde_json::from_str(&raw).map_err(|_| crate::Error::InvalidData)?;
            record.validate().map_err(|_| crate::Error::InvalidData)?;
            if (if by_setup {
                &record.original_setup_digest
            } else {
                &record.reference
            }) != lookup
                || record.account_id != vault.account_id()?
            {
                return Err(crate::Error::ReviewMismatch);
            }
            permission
                .check_current()
                .map_err(|_| crate::Error::Locked)?;
            source.check_current()?;
            record
        }; // Release read fences before acquiring the exact original-record lease.
        Self::prepare(
            journal,
            session,
            vault,
            native,
            &record.enrollment_ref,
            &record.manifest_ref,
            NamedRecipientPins {
                verifier_signing: record.verifier_signing_public_key,
                verifier_transport: record.verifier_transport_public_key,
                witness_transport: record.witness_transport_public_key,
                witness_certificate_digest: record.witness_certificate_digest.clone(),
                return_transport: record.return_transport_public_key,
            },
        )
    }
    pub(crate) fn prepare(
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
        native: &NativeAuthority,
        enrollment_ref: &str,
        manifest_ref: &str,
        pins: NamedRecipientPins,
    ) -> crate::Result<Self> {
        native.check_current()?;
        let source = native.binding();
        let records = journal
            .acquire_preconstruction_records(enrollment_ref, manifest_ref, session)
            .map_err(|_| crate::Error::Locked)?;
        records
            .require_native_origin(&source)
            .map_err(|_| crate::Error::Locked)?;
        let account_id = vault.account_id()?;
        let fvk_digest = hex::encode(Sha256::digest(vault.account().fvk()?.to_bytes()));
        if vault.account().recovery_required()
            || records.enrollment().account_id() != account_id
            || records.enrollment().account_fvk_digest() != fvk_digest
            || pins.verifier_signing == [0; 32]
        {
            return Err(crate::Error::ReviewMismatch);
        }
        for key in [
            pins.verifier_transport,
            pins.witness_transport,
            pins.return_transport,
        ] {
            TransportPublicKey::from_bytes(key).map_err(|_| crate::Error::InvalidData)?;
        }
        hash(&pins.witness_certificate_digest).map_err(|_| crate::Error::InvalidData)?;
        let proposal =
            wholepact_core::Proposal::validate(records.manifest().proposal_input().clone())
                .map_err(|_| crate::Error::Verification)?;
        let manifest = proposal.manifest();
        if proposal.manifest_digest() != records.manifest().manifest_digest()
            || proposal.proposal_digest() != records.manifest().proposal_digest()
            || manifest.agreement.privacy_profile.mode
                != wholepact_core::PrivacyMode::DeclaredOperator
            || !manifest
                .agreement
                .privacy_profile
                .dedicated_accounts_required
            || !manifest
                .agreement
                .privacy_profile
                .proving_operator
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
        {
            return Err(crate::Error::ReviewMismatch);
        }
        let mut record = NamedRecipientProfileRecordV1 {
            schema_version: 1,
            reference: String::new(),
            account_id,
            full_viewing_key_digest: fvk_digest,
            enrollment_ref: enrollment_ref.into(),
            manifest_ref: manifest_ref.into(),
            native_review_digest: String::new(),
            native_origin_digest: source.entry_digest().into(),
            original_setup_digest: String::new(),
            verifier_signing_public_key: pins.verifier_signing,
            verifier_transport_public_key: pins.verifier_transport,
            witness_transport_public_key: pins.witness_transport,
            witness_certificate_digest: pins.witness_certificate_digest,
            return_transport_public_key: pins.return_transport,
            transport_public_key: [0; 32],
            transport_secret: [0; 32],
        };
        record.original_setup_digest = record
            .setup_digest()
            .map_err(|_| crate::Error::InvalidData)?;
        let digest = digest(
            "wholepact:native-named-recipient-setup-review:v1",
            &(
                &record.original_setup_digest,
                source.entry_digest(),
                proposal.proposal_digest(),
            ),
        )
        .map_err(|_| crate::Error::InvalidData)?;
        record.native_review_digest = digest.clone();
        let display = format!(
            "OPTIONAL NAMED-VERIFIER OFFLINE PROFILE\nAccount: {}\nAccepted manifest: {}\nVerifier signing key: {}\nVerifier transport key: {}\nWitness transport key: {}\nWitness certificate: {}\nReturn destination key: {}\nSetup commitment: {}\nYou trust this exact verifier to attribute peers' inputs and returns. A dishonest verifier may misrepresent their contributions. Your own effects remain independently checked. Peer viewing keys are not shared with you. This setup does not authorize signing, spending or witness reservations. Original deadlines and unknown external-clone exposure remain. Confirm these pins through your independently authenticated source. CURRENT IMPLEMENTATION LIMIT: retaining even this setup-only immutable profile blocks existing legacy financial admission, history and recovery routes. Named financial consumers are not yet qualified. Cancelling this screen cannot remove the retained profile.",
            record.account_id,
            record.manifest_ref,
            hex::encode(record.verifier_signing_public_key),
            hex::encode(record.verifier_transport_public_key),
            hex::encode(record.witness_transport_public_key),
            record.witness_certificate_digest,
            hex::encode(record.return_transport_public_key),
            record.original_setup_digest
        );
        records.check_current().map_err(|_| crate::Error::Locked)?;
        source.check_current()?;
        Ok(Self {
            record,
            journal: journal.binding(),
            source,
            created: Instant::now(),
            digest,
            display,
            #[cfg(all(test, feature = "synthetic-qualification"))]
            before_commit: None,
            #[cfg(all(test, feature = "synthetic-qualification"))]
            after_commit: None,
        })
    }
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn display(&self) -> &str {
        &self.display
    }
    pub(crate) fn approve(
        mut self,
        decision: NativeDecision,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
        vault: &AccountVault,
    ) -> crate::Result<LiveNamedRecipientProfile> {
        if decision.binding() != &self.source
            || decision.reviewed_digest() != self.digest
            || self.journal != journal.binding()
        {
            return Err(crate::Error::ReviewMismatch);
        }
        let expires = self
            .created
            .checked_add(Duration::from_secs(120))
            .ok_or(crate::Error::InvalidData)?
            .min(
                decision
                    .consumed_at()
                    .checked_add(Duration::from_secs(120))
                    .ok_or(crate::Error::InvalidData)?,
            );
        let current = || check_setup_current(&self.source, expires);
        current()?;
        // This one lease owns the journal/session read fences through commit.
        // Do not recursively acquire another fence while a writer is queued.
        let records = journal
            .acquire_preconstruction_records(
                &self.record.enrollment_ref,
                &self.record.manifest_ref,
                session,
            )
            .map_err(|_| crate::Error::Locked)?;
        records
            .require_native_origin(&self.source)
            .map_err(|_| crate::Error::Locked)?;
        if vault.account().recovery_required()
            || vault.account_id()? != self.record.account_id
            || hex::encode(Sha256::digest(vault.account().fvk()?.to_bytes()))
                != self.record.full_viewing_key_digest
            || records.enrollment().account_fvk_digest() != self.record.full_viewing_key_digest
        {
            return Err(crate::Error::ReviewMismatch);
        }
        let mut c = journal
            .connection
            .lock()
            .map_err(|_| crate::Error::ConsentJournal(JournalError::Database))?;
        let tx = c
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| crate::Error::ConsentJournal(JournalError::Database))?;
        // Exact original lookup precedes entropy generation. A fresh approval
        // after an uncertain commit cannot replace the original transport key.
        let old: Option<String> = tx.query_row(
            "SELECT payload FROM signer_named_recipient_profiles WHERE original_setup_digest=?1",
            [&self.record.original_setup_digest], |r| r.get(0),
        ).optional().map_err(|_| crate::Error::ConsentJournal(JournalError::Database))?;
        if let Some(old) = old {
            let old = Zeroizing::new(old);
            let record: NamedRecipientProfileRecordV1 =
                serde_json::from_str(&old).map_err(|_| crate::Error::InvalidData)?;
            record.validate().map_err(|_| crate::Error::InvalidData)?;
            if record.original_setup_digest != self.record.original_setup_digest {
                return Err(crate::Error::ReviewMismatch);
            }
            records.check_current().map_err(|_| crate::Error::Locked)?;
            current()?;
            drop(tx);
            return Ok(LiveNamedRecipientProfile {
                record,
                journal: self.journal,
                source: self.source,
            });
        }
        current()?;
        getrandom::fill(&mut self.record.transport_secret)
            .map_err(|_| crate::Error::InvalidData)?;
        let secret = TransportSecret::from_bytes(self.record.transport_secret)
            .map_err(|_| crate::Error::InvalidData)?;
        self.record.transport_public_key = *secret
            .public_key()
            .map_err(|_| crate::Error::InvalidData)?
            .as_bytes();
        self.record.reference = self
            .record
            .reference_digest()
            .map_err(|_| crate::Error::InvalidData)?;
        self.record
            .validate()
            .map_err(|_| crate::Error::InvalidData)?;
        let raw = encode(&self.record).map_err(|_| crate::Error::InvalidData)?;
        tx.execute("INSERT INTO signer_named_recipient_profiles(reference,account_id,enrollment_ref,manifest_ref,original_setup_digest,payload) VALUES(?1,?2,?3,?4,?5,?6)", params![self.record.reference, self.record.account_id, self.record.enrollment_ref, self.record.manifest_ref, self.record.original_setup_digest, raw.as_str()]).map_err(|_| crate::Error::ConsentJournal(JournalError::Database))?;
        storage::bounded(&tx, journal.capacity_limits())
            .map_err(|_| crate::Error::ConsentJournal(JournalError::Database))?;
        #[cfg(all(test, feature = "synthetic-qualification"))]
        if let Some(before_commit) = self.before_commit.take() {
            before_commit();
        }
        records.check_current().map_err(|_| crate::Error::Locked)?;
        let fence = self.source.publication_lease()?;
        records.check_current().map_err(|_| crate::Error::Locked)?;
        current()?;
        tx.commit().map_err(|_| crate::Error::Uncertain)?;
        #[cfg(all(test, feature = "synthetic-qualification"))]
        if let Some(after_commit) = self.after_commit.take() {
            after_commit();
        }
        // The immutable setup key is the recovery target on any late failure.
        records
            .check_current()
            .map_err(|_| crate::Error::Uncertain)?;
        current().map_err(|_| crate::Error::Uncertain)?;
        drop(fence);
        Ok(LiveNamedRecipientProfile {
            record: self.record,
            journal: self.journal,
            source: self.source,
        })
    }
}
impl LiveNamedRecipientProfile {
    /// UI-only association polling. This deliberately reads no journal/session
    /// locks and grants no authority. Every actual operation still acquires the
    /// genuine current session and exact persisted records inside its worker.
    pub(crate) fn check_display_association(
        &self,
        journal: &SignerConsentJournal,
        native: &NativeAuthority,
    ) -> crate::Result<()> {
        native.check_current()?;
        self.source.check_current()?;
        if self.journal != journal.binding() || self.source != native.binding() {
            return Err(crate::Error::Locked);
        }
        Ok(())
    }
    pub(crate) fn check_current(
        &self,
        journal: &SignerConsentJournal,
        session: &SignerConsentSession,
    ) -> crate::Result<()> {
        self.source.check_current()?;
        if self.journal != journal.binding() {
            return Err(crate::Error::Locked);
        }
        let records = journal
            .acquire_preconstruction_records(
                &self.record.enrollment_ref,
                &self.record.manifest_ref,
                session,
            )
            .map_err(|_| crate::Error::Locked)?;
        records
            .require_native_origin(&self.source)
            .map_err(|_| crate::Error::Locked)?;
        records.check_current().map_err(|_| crate::Error::Locked)
    }
    pub(crate) fn reference(&self) -> &str {
        &self.record.reference
    }
    pub(crate) fn transport_public_key(&self) -> &[u8; 32] {
        &self.record.transport_public_key
    }
}

/// The final commit predicate remains independent of the SQLite mutex.
fn check_setup_current(source: &NativeAuthorityBinding, expires: Instant) -> crate::Result<()> {
    source.check_current()?;
    if Instant::now() >= expires {
        return Err(crate::Error::Locked);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn final_setup_predicate_rejects_original_expiry_and_revoked_source() {
        let native = crate::native_ui::recovery_test_authority();
        let source = native.binding();
        let future = Instant::now() + Duration::from_secs(5);
        assert!(check_setup_current(&source, future).is_ok());
        assert!(check_setup_current(&source, Instant::now()).is_err());
        drop(native);
        assert!(check_setup_current(&source, future).is_err());
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod transaction_tests;

mod inbox;

pub(crate) use inbox::{
    NamedIntentExportTemplate, NamedRecipientOriginalInputs, PreparedNamedIntentFileExport,
    PreparedNamedRecipientOriginalImport, RetainedNamedIntentExport,
};

#[cfg(all(test, feature = "synthetic-qualification"))]
mod joined_fixture;
pub(crate) use inbox::PreparedNamedRecipientReturnFile;
pub(crate) use inbox::{NamedRecipientOperation, PreparedNamedRecipientSigning};
