//! Private consumers of the genuine full-workflow origin receivers. No runtime
//! source-opening caller or issuer is installed by this module.
//! This account-only entry never opens owner TLS keys or authorizes Read.
use super::coordinated_public_custody_v2::{
    OpenedCoordinatedOriginalFinancialSourceV2, OriginalReadObservationV2,
};
use super::*;
use crate::account::birth::enrollment::roster_v2::durable_entry_v1::OriginalFinancialReentrySelectionV1;
use crate::native_peer::PeerProcess;
use wholepact_financial_coordinator_origin::{
    SignerSourceEntryFactsV1, SignerSourceEntryFinalV1, SignerSourceEntryInputV1,
    SignerSourceEntryPresentationV1,
};

/// Inert preparation only. The completed V3 owner and its sealed selection
/// remain with the caller through Offer/native review; this owns no source,
/// password, Host peer or permission. There is deliberately no Clone or serde.
pub(crate) struct PreparedCoordinatedSourceEntryV1 {
    facts: SignerSourceEntryFactsV1,
    original_material_deadline: Instant,
    original_source_deadline: Instant,
    original_entry_deadline: Instant,
}

fn wall_now() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Locked)?
            .as_millis(),
    )
    .map_err(|_| Error::Locked)
}

fn disclosure_digest(selection: &OriginalFinancialReentrySelectionV1) -> Result<String> {
    wholepact_core::proposal::canonical_digest(
        "wholepact:coordinated-original-financial-disclosure:v1",
        selection.disclosure(),
    )
    .map_err(|_| Error::InvalidData)
}

impl PreparedCoordinatedSourceEntryV1 {
    /// Freeze once before the first Offer. Session data is ordinary proposed
    /// binding only; the actual origin fills/authenticates actors separately.
    /// The caller supplies the actual Some(material) retained by V3, never an
    /// expired Read lease or a reconstructed material allowance.
    pub(crate) fn prepare(
        selection: &OriginalFinancialReentrySelectionV1,
        original_material_deadline: Instant,
        original_host: &PeerProcess,
        session_digest: String,
    ) -> Result<Self> {
        selection.check_host(original_host)?;
        let monotonic_now = Instant::now();
        let now = wall_now()?;
        let terms = selection.terms();
        terms.require_live(now).map_err(|_| Error::Locked)?;
        let financial_ceiling = monotonic_now
            .checked_add(Duration::from_millis(
                terms.valid_until_ms.checked_sub(now).ok_or(Error::Locked)?,
            ))
            .ok_or(Error::InvalidData)?;
        let original_source_deadline = original_material_deadline.min(financial_ceiling);
        let original_entry_deadline = original_source_deadline.min(
            monotonic_now
                .checked_add(Duration::from_secs(120))
                .ok_or(Error::InvalidData)?,
        );
        let entry_ms = u64::try_from(
            original_entry_deadline
                .checked_duration_since(monotonic_now)
                .ok_or(Error::Locked)?
                .as_millis(),
        )
        .map_err(|_| Error::InvalidData)?;
        let facts = SignerSourceEntryFactsV1 {
            selection_digest: selection.digest().to_owned(),
            display: selection.display()?,
            original_host_process_instance: original_host.instance().to_owned(),
            account_id: terms.scope.authorization.identity.account_id.clone(),
            owner_certificate_digest: selection.owner_certificate_digest().to_owned(),
            disclosure_digest: disclosure_digest(selection)?,
            terms_digest: terms
                .intent_terms_digest()
                .map_err(|_| Error::InvalidData)?,
            session_digest,
            reviewed_at_ms: now,
            expires_at_ms: now.checked_add(entry_ms).ok_or(Error::InvalidData)?,
            source_expires_at_ms: terms.valid_until_ms,
        };
        facts.validate()?;
        let result = Self {
            facts,
            original_material_deadline,
            original_source_deadline,
            original_entry_deadline,
        };
        result.check_selection(selection, original_material_deadline, original_host)?;
        Ok(result)
    }

    pub(crate) fn facts(&self) -> &SignerSourceEntryFactsV1 {
        &self.facts
    }
    pub(crate) fn original_source_deadline(&self) -> Instant {
        self.original_source_deadline
    }
    pub(crate) fn original_entry_deadline(&self) -> Instant {
        self.original_entry_deadline
    }

    fn check_selection(
        &self,
        selection: &OriginalFinancialReentrySelectionV1,
        original_material_deadline: Instant,
        original_host: &PeerProcess,
    ) -> Result<()> {
        self.facts.validate()?;
        selection.check_host(original_host)?;
        let now = wall_now()?;
        let terms = selection.terms();
        terms.require_live(now).map_err(|_| Error::Locked)?;
        if self.original_material_deadline != original_material_deadline
            || self.original_source_deadline > original_material_deadline
            || self.original_entry_deadline > self.original_source_deadline
            || Instant::now() >= self.original_entry_deadline
            || now < self.facts.reviewed_at_ms
            || now >= self.facts.expires_at_ms
            || self.facts.selection_digest != selection.digest()
            || self.facts.display != selection.display()?
            || self.facts.original_host_process_instance != original_host.instance()
            || self.facts.account_id != terms.scope.authorization.identity.account_id
            || self.facts.owner_certificate_digest != selection.owner_certificate_digest()
            || self.facts.disclosure_digest != disclosure_digest(selection)?
            || self.facts.terms_digest
                != terms
                    .intent_terms_digest()
                    .map_err(|_| Error::InvalidData)?
            || self.facts.source_expires_at_ms != terms.valid_until_ms
        {
            return Err(Error::ReviewMismatch);
        }
        selection.check_host(original_host)
    }

    /// Only ordinary exact data is joined here. This does not receive/mint a
    /// Final, decrypt input, or claim that the presentation has been approved.
    pub(crate) fn freeze_presentation(
        self,
        presentation: SignerSourceEntryPresentationV1,
    ) -> Result<PresentedCoordinatedSourceEntryV1> {
        presentation.validate()?;
        if presentation.facts != self.facts {
            return Err(Error::ReviewMismatch);
        }
        Ok(PresentedCoordinatedSourceEntryV1 {
            prepared: self,
            presentation,
        })
    }
}

/// Full displayed data plus the original exact Instants, still not a grant.
pub(crate) struct PresentedCoordinatedSourceEntryV1 {
    prepared: PreparedCoordinatedSourceEntryV1,
    presentation: SignerSourceEntryPresentationV1,
}
impl PresentedCoordinatedSourceEntryV1 {
    pub(crate) fn presentation(&self) -> &SignerSourceEntryPresentationV1 {
        &self.presentation
    }
    fn check_final(
        &self,
        selection: &OriginalFinancialReentrySelectionV1,
        original_material_deadline: Instant,
        original_host: &PeerProcess,
        admission: &SignerSourceEntryFinalV1,
    ) -> Result<()> {
        admission.check_current()?;
        self.presentation.validate()?;
        self.prepared
            .check_selection(selection, original_material_deadline, original_host)?;
        if self.presentation.facts != self.prepared.facts
            || admission.selection_digest() != selection.digest()
            || admission.presentation_digest() != self.presentation.presentation_digest
            || admission.original_host_process_instance() != original_host.instance()
            || admission.original_source_deadline() != self.prepared.original_source_deadline
            || admission.original_entry_deadline() != self.prepared.original_entry_deadline
        {
            return Err(Error::ReviewMismatch);
        }
        admission.check_current()?;
        Ok(())
    }
}

impl PreparedOriginalFinancialSourceV1 {
    /// Fresh original-file entry after the old V3 revoke/drop sequence. No
    /// PendingAccountNativeAuthority is fabricated or inherited. Input, ticket
    /// and Final are consumed on every result and can never be retried here.
    pub(crate) fn open_coordinated_original19(
        selection: OriginalFinancialReentrySelectionV1,
        original_material_deadline: Instant,
        original_host: &PeerProcess,
        presented: PresentedCoordinatedSourceEntryV1,
        input: SignerSourceEntryInputV1,
        admission: SignerSourceEntryFinalV1,
    ) -> Result<OpenedCoordinatedOriginalFinancialSourceV2> {
        let check = || {
            presented.check_final(
                &selection,
                original_material_deadline,
                original_host,
                &admission,
            )
        };
        check()?;
        let password = input.open(&admission)?;
        check()?;
        require_canonical_existing_root(selection.root())?;
        check()?;
        let directory = PrivateDirectory::open_existing(selection.root())?;
        check()?;
        let encrypted = directory.read("account.wp", 512 * 1024)?;
        check()?;
        // The existing maintained KDF/original-account decoder is unchanged.
        // The independent origin control owner continues observing global R.
        let account = Arc::new(active::open_for_coordinated_financial_source_entry_v1(
            directory, &password, &encrypted, &admission,
        )?);
        drop(password);
        check()?;
        original(&account)?;
        check()?;
        super::super::roster_inventory(&account.directory)?;
        check()?;
        let retained = super::super::read_roster_retained(account.clone())?;
        check()?;
        retained.check()?;
        check()?;
        let original_commit = publication::read_commit(&retained)?;
        check()?;
        let original_disclosure = retained.disclosure()?;
        check()?;
        let genesis = &retained.record.account_record.genesis;
        if genesis.identity.account_id != selection.terms().scope.authorization.identity.account_id
            || original_disclosure != *selection.disclosure()
        {
            return Err(Error::ReviewMismatch);
        }
        // Keep the existing fence type and full original19 journal audit. No
        // source/journal guard crosses any origin receive or review wait.
        let source_owner = account.directory.signer_journal_source_owner()?;
        check()?;
        let journal = SignerConsentJournal::open_coordinated_delivery_entry_v2(
            &account.directory.root().join(JOURNAL),
            &DatabaseKey::from_bytes(*retained.journal_key),
            genesis,
            &source_owner,
            &admission,
        )?;
        drop(source_owner);
        check()?;
        let binding = journal.prepare_coordinated_entry_source_binding_v2(genesis, &admission)?;
        check()?;
        let snapshot = immutable(&retained)?;
        check()?;
        selection.require_reopened(&retained, &binding)?;
        check()?;
        journal.check_coordinated_entry_source_v2(&binding, &admission)?;
        check()?;
        retained.check()?;
        check()?;
        if immutable(&retained)? != snapshot {
            return Err(Error::ReviewMismatch);
        }
        check()?;
        if publication::read_commit(&retained)? != original_commit {
            return Err(Error::ReviewMismatch);
        }
        check()?;
        // Capture ordinary return data while Final is still R-sensitive. No
        // fallible source audit is deferred until after the consuming join.
        let identity = binding.identity_digest().to_owned();
        let recipient = original_host.clone();
        let original_ceiling_ms = selection.terms().valid_until_ms;
        let original_deadline = presented.prepared.original_source_deadline;
        let observation = OriginalReadObservationV2 {
            source_identity: identity.clone(),
            journal_digest: binding.original_reentry_selection_v1()?.digest()?,
            owner_certificate_digest: retained
                .record
                .account_record
                .terms
                .signer
                .owner_certificate_digest
                .clone(),
            disclosure: original_disclosure.clone(),
            terms_digest: selection
                .terms()
                .intent_terms_digest()
                .map_err(|_| Error::InvalidData)?,
            selection_digest: selection.digest().to_owned(),
            entry_presentation_digest: presented.presentation.presentation_digest.clone(),
            original_host_instance: original_host.instance().to_owned(),
        };
        check()?;
        let lifetime = admission.into_original_custody_lifetime()?;
        let source = Self {
            retained,
            original_commit,
            original_disclosure,
            journal: OriginalJournalV1::Before(journal),
            binding: std::sync::Mutex::new(binding),
            identity,
            recipient: std::sync::Mutex::new(Some(recipient)),
            immutable: snapshot,
            lifetime: OriginalFinancialCustodyLifetimeV1::Coordinated(lifetime),
            original_ceiling_ms,
            original_deadline,
        };
        Ok(OpenedCoordinatedOriginalFinancialSourceV2 {
            source,
            observation,
        })
    }
}
