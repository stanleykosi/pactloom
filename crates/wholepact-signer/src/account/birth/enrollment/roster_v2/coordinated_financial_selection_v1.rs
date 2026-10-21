//! Data-only original selection captured from actual completed V3 custody.
//! No source owner, connection, key, grant or lifetime observer is retained.
use super::*;
use crate::authority_bridge::durable_review_ipc_v3::RecipientIntentV3;
#[cfg(feature = "coordinated-financial-workflow-v1")]
use crate::authority_bridge::durable_review_ipc_v3::coordinated_recipient_v1::CoordinatedRecipientIntentV1;

// Inert provenance choice only. Native serialization is unchanged; coordinated
// provider semantics keep their own explicit envelope and digest domain.
#[derive(serde::Serialize)]
#[serde(untagged)]
enum SelectedRecipientV1 {
    Native(RecipientIntentV3),
    #[cfg(feature = "coordinated-financial-workflow-v1")]
    Coordinated { coordinated_v1: CoordinatedRecipientIntentV1 },
}

use crate::consent_journal::{FinancialSourceBindingV1, OriginalFinancialJournalSelectionV1};
use crate::native_peer::PeerProcess;
use wholepact_authority::durable_financial_continuation_v1::FinancialContinuationTermsV1;

fn inventory_digest(files: &BTreeMap<String, FileRevisionV3>) -> Result<String> {
    let selected = files
        .iter()
        .map(|(name, f)| {
            (
                name, f.device, f.inode, f.length, f.uid, f.gid, f.mode, f.modified, f.changed,
            )
        })
        .collect::<Vec<_>>();
    wholepact_core::proposal::canonical_digest(
        "wholepact:coordinated-financial-reentry-files:v1",
        &selected,
    )
    .map_err(|_| Error::InvalidData)
}

/// Sealed inert evidence, not a source opener or permission. In particular the
/// retained journal selection contains only stable identity/genesis/row data.
pub(crate) struct OriginalFinancialReentrySelectionV1 {
    root: std::path::PathBuf,
    journal: OriginalFinancialJournalSelectionV1,
    record: BornManualRosterEnrollmentRecordV2,
    commit: publication::BornManualRosterCommitV2,
    immutable: BTreeMap<String, FileRevisionV3>,
    disclosure: wholepact_authority::WitnessDisclosureDescriptor,
    terms: FinancialContinuationTermsV1,
    recipient: SelectedRecipientV1,
    prior_source_identity: String,
    host_process_instance: String,
    digest: String,
}
impl OriginalFinancialReentrySelectionV1 {
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
    pub(crate) fn terms(&self) -> &FinancialContinuationTermsV1 {
        &self.terms
    }
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn host_process_instance(&self) -> &str {
        &self.host_process_instance
    }
    /// Ordinary exact source facts only. No password, credential key or source
    /// owner is serialized; this display cannot authorize the selected opener.
    pub(crate) fn display(&self) -> Result<String> {
        serde_json::to_string_pretty(&serde_json::json!({
            "purpose": "fresh_original_financial_source_entry_v1",
            "selected_root": self.root,
            "prior_v3_source_identity": self.prior_source_identity,
            "original_journal_digest": self.journal.digest()?,
            "original_record": self.record,
            "original_commit": self.commit,
            "immutable_inventory_digest": inventory_digest(&self.immutable)?,
            "original_witness_disclosure": self.disclosure,
            "financial_terms": self.terms,
            "original_recipient": self.recipient,
            "original_host_process_instance": self.host_process_instance,
            "selection_digest": self.digest,
        }))
        .map_err(|_| Error::InvalidData)
    }
    pub(crate) fn disclosure(&self) -> &wholepact_authority::WitnessDisclosureDescriptor {
        &self.disclosure
    }
    pub(crate) fn owner_certificate_digest(&self) -> &str {
        &self
            .record
            .account_record
            .terms
            .signer
            .owner_certificate_digest
    }
    pub(crate) fn check_host(&self, peer: &PeerProcess) -> Result<()> {
        peer.check_alive()?;
        if peer.instance() != self.host_process_instance {
            return Err(Error::Authentication);
        }
        peer.check_alive()?;
        Ok(())
    }
    /// The caller must already hold a genuinely reopened, fully audited source.
    /// Equality of this data never opens a source or restores any permission.
    pub(in crate::account::birth::enrollment::roster_v2) fn require_reopened(
        &self,
        retained: &RetainedBornManualRosterEnrollmentV2,
        journal: &FinancialSourceBindingV1,
    ) -> Result<()> {
        retained.check()?;
        if retained.account.directory.root() != self.root.as_path()
            || retained.record != self.record
            || publication::read_commit(retained)? != self.commit
            || retained.disclosure()? != self.disclosure
            || immutable_files(retained)? != self.immutable
        {
            return Err(Error::ReviewMismatch);
        }
        self.journal.require_reopened(journal)?;
        retained.check()
    }
}

impl ActivePreparedDeliverySourceV3 {
    /// Called only by the private completed-role handoff, before its unchanged
    /// revoke/drop sequence. No old Read permission is extended or inherited.
    pub(crate) fn capture_financial_reentry_selection_v1(
        &self,
        terms: &FinancialContinuationTermsV1,
        recipient: &RecipientIntentV3,
        peer: &PeerProcess,
    ) -> Result<OriginalFinancialReentrySelectionV1> {
        self.source.check_custody()?;
        terms.validate().map_err(|_| Error::ReviewMismatch)?;
        recipient.validate().map_err(|_| Error::ReviewMismatch)?;
        peer.check_alive()?;
        let (enrollment, manifest, disclosure, _) = self.source.history_setup_metadata()?;
        if self.source.identity() != recipient.source_identity_digest
            || peer.instance() != recipient.authorized_host_process_instance
            || terms.original_recipient_intent_digest
                != recipient.digest().map_err(|_| Error::ReviewMismatch)?
            || terms.original_recipient_enrollment_ref != enrollment.reference()
            || terms.original_recipient_manifest_ref != manifest.reference()
            || recipient.original_enrollment_ref != enrollment.reference()
            || recipient.original_manifest_ref != manifest.reference()
            || terms.scope.witness != disclosure
            || terms.scope.authorization.identity.account_id
                != self
                    .source
                    .retained
                    .record
                    .account_record
                    .genesis
                    .identity
                    .account_id
        {
            return Err(Error::ReviewMismatch);
        }
        let binding = self.source.journal.prepare_financial_source_binding_v1(
            &self.source.retained.record.account_record.genesis,
        )?;
        let journal = binding.original_reentry_selection_v1()?;
        let immutable = immutable_files(&self.source.retained)?;
        let commit = publication::read_commit(&self.source.retained)?;
        let root = self.source.root().to_path_buf();
        let record = self.source.retained.record.clone();
        let host_process_instance = peer.instance().to_owned();
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:coordinated-financial-reentry-selection:v1",
            &(
                &root,
                self.source.identity(),
                journal.digest()?,
                &record,
                &commit,
                inventory_digest(&immutable)?,
                &disclosure,
                terms,
                recipient,
                &host_process_instance,
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        let selection = OriginalFinancialReentrySelectionV1 {
            root,
            journal,
            record,
            commit,
            immutable,
            disclosure,
            terms: terms.clone(),
            recipient: SelectedRecipientV1::Native(recipient.clone()),
            prior_source_identity: self.source.identity().to_owned(),
            host_process_instance,
            digest,
        };
        selection.require_reopened(&self.source.retained, &binding)?;
        self.source
            .journal
            .check_financial_source_binding_v1(&binding)?;
        self.source.check_custody()?;
        selection.check_host(peer)?;
        Ok(selection)
    }

    /// Recheck the exact retained original selection after a review wait. This
    /// returns no permission and holds no source/journal lock on return.
    pub(crate) fn check_financial_reentry_selection_v1(
        &self,
        selection: &OriginalFinancialReentrySelectionV1,
        recipient: &RecipientIntentV3,
        peer: &PeerProcess,
    ) -> Result<()> {
        self.source.check_custody()?;
        if self.source.identity() != selection.prior_source_identity
            || !matches!(&selection.recipient, SelectedRecipientV1::Native(actual) if actual == recipient)
        {
            return Err(Error::ReviewMismatch);
        }
        selection.check_host(peer)?;
        let binding = self.source.journal.prepare_financial_source_binding_v1(
            &self.source.retained.record.account_record.genesis,
        )?;
        selection.require_reopened(&self.source.retained, &binding)?;
        self.source
            .journal
            .check_financial_source_binding_v1(&binding)?;
        self.source.check_custody()?;
        selection.check_host(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inert_reentry_inventory_digest_binds_each_original_file_fact() {
        let original = || {
            BTreeMap::from([(
                "account.wp".to_owned(),
                FileRevisionV3 {
                    device: 1,
                    inode: 2,
                    length: 3,
                    uid: 4,
                    gid: 5,
                    mode: 0o600,
                    modified: (6, 7),
                    changed: (8, 9),
                },
            )])
        };
        let expected = inventory_digest(&original()).unwrap();
        for field in 0..11 {
            let mut changed = original();
            let value = changed.get_mut("account.wp").unwrap();
            match field {
                0 => value.device += 1,
                1 => value.inode += 1,
                2 => value.length += 1,
                3 => value.uid += 1,
                4 => value.gid += 1,
                5 => value.mode ^= 0o100,
                6 => value.modified.0 += 1,
                7 => value.modified.1 += 1,
                8 => value.changed.0 += 1,
                9 => value.changed.1 += 1,
                _ => {
                    let value = changed.remove("account.wp").unwrap();
                    changed.insert("other.wp".into(), value);
                }
            }
            assert_ne!(inventory_digest(&changed).unwrap(), expected);
        }
        assert_ne!(inventory_digest(&BTreeMap::new()).unwrap(), expected);
    }
}

#[cfg(feature = "coordinated-financial-workflow-v1")]
impl OriginalFinancialReentrySelectionV1 {
    /// Private producer invoked only by the same actual source's Audit consumer.
    /// Every private file observation remains under that concrete fresh Final.
    pub(in crate::account::birth::enrollment::roster_v2::durable_entry_v1) fn capture_coordinated_under_audit_v1(
        retained: &RetainedBornManualRosterEnrollmentV2,
        binding: &FinancialSourceBindingV1,
        terms: &FinancialContinuationTermsV1,
        recipient: &CoordinatedRecipientIntentV1,
        source_identity: &str,
        peer: &PeerProcess,
        action: &wholepact_financial_coordinator_origin::SignerV3AuditFinalV1,
    ) -> Result<Self> {
        action.check_current()?;
        terms.validate().map_err(|_| Error::ReviewMismatch)?;
        recipient.validate().map_err(|_| Error::ReviewMismatch)?;
        peer.check_alive()?;
        if action.facts().received.source_identity_digest != source_identity
            || action.facts().received.recipient_intent_digest != recipient.digest().map_err(|_|Error::ReviewMismatch)?
            || recipient.source_identity_digest != source_identity
            || peer.instance() != recipient.authorized_host_process_instance
            || terms.original_recipient_intent_digest != recipient.digest().map_err(|_|Error::ReviewMismatch)?
            || terms.original_recipient_enrollment_ref != recipient.original_enrollment_ref
            || terms.original_recipient_manifest_ref != recipient.original_manifest_ref
            || terms.scope.authorization.identity.account_id != retained.record.account_record.genesis.identity.account_id
        { return Err(Error::ReviewMismatch); }
        retained.check()?;
        action.check_current()?;
        let journal = binding.original_reentry_selection_v1()?;
        let immutable = immutable_files(retained)?;
        let commit = publication::read_commit(retained)?;
        let disclosure = retained.disclosure()?;
        action.check_current()?;
        if terms.scope.witness != disclosure { return Err(Error::ReviewMismatch); }
        let root = retained.account.directory.root().to_path_buf();
        let record = retained.record.clone();
        let host_process_instance = peer.instance().to_owned();
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:coordinated-v3-financial-reentry-selection:v1",
            &(&root, source_identity, journal.digest()?, &record, &commit,
              inventory_digest(&immutable)?, &disclosure, terms, recipient, &host_process_instance),
        ).map_err(|_| Error::InvalidData)?;
        let selected = Self {
            root, journal, record, commit, immutable, disclosure, terms: terms.clone(),
            recipient: SelectedRecipientV1::Coordinated { coordinated_v1: recipient.clone() },
            prior_source_identity: source_identity.into(), host_process_instance, digest,
        };
        selected.require_reopened(retained,binding)?;
        peer.check_alive()?;
        action.check_current()?;
        Ok(selected)
    }
}
