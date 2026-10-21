//! Entry-frozen observations are data, never private-read authority. Before a
//! genuine Read, only actor/lifetime, file metadata and SQLite identity/revision
//! currentness are sampled. Legacy native custody checks remain unchanged.
use super::*;
use wholepact_financial_coordinator_origin::SignerFinancialReadFinalV1;

pub(super) struct OriginalReadObservationV2 {
    pub(super) source_identity: String,
    pub(super) journal_digest: String,
    pub(super) owner_certificate_digest: String,
    pub(super) disclosure: wholepact_authority::WitnessDisclosureDescriptor,
    pub(super) terms_digest: String,
    pub(super) selection_digest: String,
    pub(super) entry_presentation_digest: String,
    pub(super) original_host_instance: String,
}

/// Created only by the actual Entry opener after its complete audit and before
/// consuming Entry Final. No caller constructor, Clone, serde or key getter.
/// Its exact source moves into Read, not a separately supplied replacement.
pub(crate) struct OpenedCoordinatedOriginalFinancialSourceV2 {
    pub(super) source: PreparedOriginalFinancialSourceV1,
    pub(super) observation: OriginalReadObservationV2,
}
impl OpenedCoordinatedOriginalFinancialSourceV2 {
    pub(crate) fn original_root(&self) -> &Path {
        self.source.original_root()
    }
    pub(crate) fn identity_digest(&self) -> &str {
        &self.observation.source_identity
    }
    pub(crate) fn original_deadline(&self) -> Instant {
        self.source.original_deadline
    }
    pub(crate) fn original_ceiling_ms(&self) -> u64 {
        self.source.original_ceiling_ms
    }
    pub(crate) fn journal_digest(&self) -> &str {
        &self.observation.journal_digest
    }
    pub(crate) fn entry_presentation_digest(&self) -> &str {
        &self.observation.entry_presentation_digest
    }
    pub(crate) fn selection_digest(&self) -> &str {
        &self.observation.selection_digest
    }
    pub(crate) fn terms_digest(&self) -> &str {
        &self.observation.terms_digest
    }
    pub(crate) fn require_owner(
        &self,
        disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        certificate: &str,
    ) -> Result<()> {
        if &self.observation.disclosure != disclosure
            || self.observation.owner_certificate_digest != certificate
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(crate) fn check_public(&self, host: &crate::native_peer::PeerProcess) -> Result<()> {
        self.source.check_coordinated_public_custody_v2(host)?;
        if self.source.identity != self.observation.source_identity
            || host.instance() != self.observation.original_host_instance
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(crate) fn into_read(
        self,
        read: &SignerFinancialReadFinalV1,
    ) -> Result<PreparedOriginalFinancialSourceV1> {
        read.check_current()?;
        let p = read.presentation();
        if p.facts.source_identity_digest != self.observation.source_identity
            || p.facts.original_journal_digest != self.observation.journal_digest
            || p.facts.terms_digest != self.observation.terms_digest
            || p.selection_digest != self.observation.selection_digest
            || p.source_entry_presentation_digest != self.observation.entry_presentation_digest
            || p.facts.owner_certificate_digest != self.observation.owner_certificate_digest
            || p.facts.account_id != self.observation.disclosure.account_id
            || p.facts.disclosure_digest
                != wholepact_core::proposal::canonical_digest(
                    "wholepact:coordinated-original-financial-disclosure:v1",
                    &self.observation.disclosure,
                )
                .map_err(|_| Error::InvalidData)?
            || p.facts.source_expires_at_ms != self.source.original_ceiling_ms
            || p.facts.original_host_process_instance != self.observation.original_host_instance
            || read.original_source_deadline() != self.source.original_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        self.source.check_coordinated_read_custody_v2(read)?;
        read.check_current()?;
        Ok(self.source)
    }
}

impl PreparedOriginalFinancialSourceV1 {
    /// No original record, commit, row, enrollment or intent content is read.
    pub(crate) fn check_coordinated_public_custody_v2(
        &self,
        host: &crate::native_peer::PeerProcess,
    ) -> Result<()> {
        self.lifetime.check_connected()?;
        if !matches!(
            &self.lifetime,
            OriginalFinancialCustodyLifetimeV1::Coordinated(_)
        ) || Instant::now() >= self.original_deadline
        {
            return Err(Error::Locked);
        }
        host.check_alive()?;
        {
            let held = self.recipient.lock().map_err(|_| Error::Locked)?;
            let original = held.as_ref().ok_or(Error::Authentication)?;
            if original.instance() != host.instance() {
                return Err(Error::Authentication);
            }
            original.same_live_process(host)?;
        }
        // immutable() enumerates only allowed names and file metadata. It does
        // not call retained.check(), read_commit() or read/decrypt file contents.
        if immutable(&self.retained)? != self.immutable {
            return Err(Error::ReviewMismatch);
        }
        {
            let binding = self.binding.lock().map_err(|_| Error::Locked)?;
            self.lifetime.check_connected()?;
            match &self.journal {
                OriginalJournalV1::Before(journal) => {
                    journal.check_coordinated_public_pin_v2(&binding)?
                }
                OriginalJournalV1::Financial(journal) => {
                    journal.check_coordinated_public_pin_v2(&binding)?
                }
            }
        }
        self.lifetime.check_connected()?;
        host.check_alive()?;
        Ok(())
    }

    /// Expected original owner data was authenticated by Entry and is retained
    /// in memory. Matching it is neither a semantic reread nor permission.
    pub(crate) fn require_coordinated_owner_metadata_v2(
        &self,
        disclosure: &wholepact_authority::WitnessDisclosureDescriptor,
        certificate: &str,
    ) -> Result<()> {
        if !matches!(
            &self.lifetime,
            OriginalFinancialCustodyLifetimeV1::Coordinated(_)
        ) || &self.original_disclosure != disclosure
            || self
                .retained
                .record
                .account_record
                .terms
                .signer
                .owner_certificate_digest
                != certificate
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }

    pub(crate) fn coordinated_public_journal_digest_v2(&self) -> Result<String> {
        if !matches!(
            &self.lifetime,
            OriginalFinancialCustodyLifetimeV1::Coordinated(_)
        ) || !matches!(&self.journal, OriginalJournalV1::Before(_))
        {
            return Err(Error::Unavailable);
        }
        let binding = self.binding.lock().map_err(|_| Error::Locked)?;
        Ok(binding.original_reentry_selection_v1()?.digest()?)
    }

    /// Full semantic rereads are permitted only by this exact unconsumed Read.
    /// The journal checks its token again after each binding/fence/connection/
    /// transaction acquisition, before inspecting any private rows.
    pub(crate) fn check_coordinated_read_custody_v2(
        &self,
        read: &SignerFinancialReadFinalV1,
    ) -> Result<()> {
        let check = || -> Result<()> {
            read.check_current()?;
            if !matches!(
                &self.lifetime,
                OriginalFinancialCustodyLifetimeV1::Coordinated(_)
            ) || read.presentation().facts.source_identity_digest != self.identity
                || read.original_source_deadline() != self.original_deadline
                || read.presentation().facts.source_expires_at_ms != self.original_ceiling_ms
            {
                return Err(Error::ReviewMismatch);
            }
            self.lifetime.check_connected()
        };
        check()?;
        self.retained.check()?;
        check()?;
        if immutable(&self.retained)? != self.immutable {
            return Err(Error::ReviewMismatch);
        }
        check()?;
        if publication::read_commit(&self.retained)? != self.original_commit {
            return Err(Error::ReviewMismatch);
        }
        check()?;
        {
            let binding = self.binding.lock().map_err(|_| Error::Locked)?;
            check()?;
            match &self.journal {
                OriginalJournalV1::Before(journal) => {
                    journal.check_coordinated_read_source_v2(&binding, read)?
                }
                OriginalJournalV1::Financial(_) => return Err(Error::RecoveryRequired),
            }
        }
        check()
    }
}
