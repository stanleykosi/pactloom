//! Wallet-only read selection within the sealed archive materializer. These
//! methods never expose the temporary path, keys or a writable journal handle.
use super::*;
use crate::bundle::recovery::wallet_templates;

impl ArchivedJournal<'_> {
    /// Select a complete ordinary wallet layout, then let the existing immutable
    /// archive reader authenticate exact rows and attach its sealed origin.
    pub fn inspect_wallet_ordinary_with_templates<const N: usize>(
        &self,
        key: &DatabaseKey,
        templates: [&'static JournalTemplate; N],
    ) -> Result<ArchivedOrdinarySource> {
        let directory = self.materialize()?;
        let snapshot =
            crate::open_encrypted_read_snapshot(directory.path().join("journal.sqlite"), key)?;
        let template = wallet_templates::for_read_snapshot(&snapshot, templates)?;
        drop(snapshot);
        self.inspect_ordinary(key, template)
    }

    /// Select an exact immutable-wallet-evidence layout without trusting version
    /// labels. The existing reader rechecks original path, generation, complete
    /// component descriptors and rows, then retains sealed archive provenance.
    pub fn open_wallet_evidence_with_templates<const N: usize>(
        &self,
        key: &DatabaseKey,
        binding: &GenerationBinding,
        expected: &RecoveryProvenance,
        templates: [&'static JournalTemplate; N],
    ) -> Result<RecoveredEvidence> {
        let directory = self.materialize()?;
        let template = wallet_templates::for_evidence_file(
            &directory.path().join("journal.sqlite"),
            key,
            templates,
        )?;
        self.open_evidence(key, binding, expected, template)
    }
}
