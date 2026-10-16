mod wallet_templates;

use super::*;
use crate::bundle::{
    self,
    recovery::{
        evidence::{self, RecoveredEvidence},
        generation::{self, GenerationBinding},
    },
};

impl VerifiedArchive {
    pub(super) fn visit_object(
        &self,
        id: &str,
        mut visitor: impl FnMut(usize, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let length = *self.objects.get(id).ok_or(ArchiveError::Integrity)?;
        let mut statement = self.snapshot.prepare(
            "SELECT ordinal,payload FROM archive_chunks WHERE digest=?1 ORDER BY ordinal",
        )?;
        let mut rows = statement.query([id])?;
        let mut offset = 0u64;
        let mut ordinal = 0usize;
        while let Some(row) = rows.next()? {
            let index: usize = row.get(0)?;
            let bytes = row
                .get_ref(1)?
                .as_blob()
                .map_err(|_| ArchiveError::Integrity)?;
            let wanted = (length - offset).min(CHUNK_BYTES as u64) as usize;
            if index != ordinal || wanted == 0 || bytes.len() != wanted {
                return Err(ArchiveError::Integrity);
            }
            visitor(ordinal, bytes)?;
            offset += bytes.len() as u64;
            ordinal += 1;
        }
        if offset != length {
            return Err(ArchiveError::Integrity);
        }
        Ok(())
    }
    pub(super) fn read_object(
        &self,
        object: &ObjectRef,
        max_bytes: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let length = usize::try_from(object.length).map_err(|_| ArchiveError::Limit)?;
        if length > max_bytes || self.objects.get(&object.digest) != Some(&object.length) {
            return Err(ArchiveError::Limit);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(length)
            .map_err(|_| ArchiveError::Limit)?;
        self.visit_object(&object.digest, |_, chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(bytes)
    }
}
impl ArchivedJournal<'_> {
    // ADD inside generation_archive/readers.rs's impl ArchivedJournal<'_>.
    // Uses its existing private ciphertext materializer. No writable handle escapes.
    pub fn verify_archived_planned_witness_empty(
        &self,
        key: &crate::DatabaseKey,
        namespace_digest: &str,
        intent_digest: &str,
        expected_original_path: &std::path::Path,
    ) -> Result<()> {
        if self.origin()
            != expected_original_path
                .to_str()
                .ok_or(ArchiveError::Invalid)?
        {
            return Err(ArchiveError::Invalid);
        }
        let directory = self.materialize()?;
        let path = directory.path().join("journal.sqlite");
        let expected = crate::PlannedWitnessBirthInitialization::new(
            namespace_digest,
            intent_digest,
            &path,
            key,
        )?;
        expected.verify_empty(&path, key, namespace_digest, intent_digest)?;
        Ok(())
    }
    pub fn origin(&self) -> &str {
        self.entry()
            .origin
            .as_deref()
            .expect("verified journal origin")
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    fn entry(&self) -> &Entry {
        &self.archive.nodes[&self.archive.manifests[&self.manifest_digest].node_digest].entries
            [&self.id]
    }
    /// Authenticate ordinary journal identity/schema without changing its source.
    pub fn open_ordinary(
        &self,
        key: &DatabaseKey,
        template: &'static JournalTemplate,
    ) -> Result<crate::EncryptedReadSnapshot> {
        let directory = self.materialize()?;
        Ok(bundle::open_journal_read_snapshot(
            &directory.path().join("journal.sqlite"),
            key,
            template,
        )?)
    }
    /// Authenticate complete typed ordinary rows for trusted host composition.
    /// Private artifact disclosure still needs its separate foreground permission.
    pub fn inspect_ordinary(
        &self,
        key: &DatabaseKey,
        template: &'static JournalTemplate,
    ) -> Result<ArchivedOrdinarySource> {
        let snapshot = self.open_ordinary(key, template)?;
        let (digest, rows, tables) =
            bundle::recovery::archive::inspect_ordinary(snapshot.connection(), template)?;
        let provenance = self.provenance(template, digest, rows);
        Ok(ArchivedOrdinarySource {
            historical_binding: HistoricalSourceBinding::fresh(),
            archive_origin: self.disclosure_origin(&provenance),
            provenance,
            tables,
        })
    }
    /// The returned source commits all CURRENT owner rows, excluding only the
    /// storage marker. The old marker provenance remains separately on snapshot.
    pub fn open_generation(
        &self,
        key: &DatabaseKey,
        binding: &GenerationBinding,
        expected: &RecoveryProvenance,
        template: &'static JournalTemplate,
    ) -> Result<ArchivedGenerationSource> {
        let directory = self.materialize()?;
        let snapshot = generation::open_archived_generation_snapshot(
            &directory.path().join("journal.sqlite"),
            Path::new(self.origin()),
            key,
            binding,
            expected,
            template,
        )?;
        let (digest, rows) =
            generation::coordination_owner_rows_commitment(snapshot.connection(), template)?;
        let provenance = self.provenance(template, digest, rows);
        Ok(ArchivedGenerationSource {
            historical_binding: HistoricalSourceBinding::fresh(),
            archive_origin: self.disclosure_origin(&provenance),
            snapshot,
            provenance,
        })
    }
    /// Retain exact inherited permanent marker and original component provenance.
    pub fn open_evidence(
        &self,
        key: &DatabaseKey,
        binding: &GenerationBinding,
        expected: &RecoveryProvenance,
        template: &'static JournalTemplate,
    ) -> Result<RecoveredEvidence> {
        use bundle::JournalKind;
        let directory = self.materialize()?;
        let path = directory.path().join("journal.sqlite");
        let origin = Path::new(self.origin());
        macro_rules! open {
            ($reader:ident) => {
                evidence::$reader(&path, origin, key, binding, expected, template)
            };
        }
        let mut source = match template.kind {
            JournalKind::CoordinationAuthority => open!(open_archived_coordination_evidence),
            JournalKind::TransportInbox => open!(open_archived_inbox_evidence),
            JournalKind::TransportOutbox => open!(open_archived_outbox_evidence),
            JournalKind::Submission => open!(open_archived_submission_evidence),
            JournalKind::ProofWitness => open!(open_archived_proof_evidence),
            JournalKind::SignedResults => open!(open_archived_signed_results_evidence),
            JournalKind::ExactTransactions => open!(open_archived_transactions_evidence),
            JournalKind::WalletScan => open!(open_archived_wallet_scan_evidence),
            JournalKind::SignerConsentAuthority => return Err(ArchiveError::Unsupported),
        }?;
        let provenance = self.provenance(
            template,
            source.provenance().component_digest.clone(),
            source.provenance().rows,
        );
        source.attach_archive_origin(self.disclosure_origin(&provenance));
        Ok(source)
    }
    /// Only invoked after the concrete journal/key/marker/schema/rows authenticate.
    /// All lineage labels come from this verified journal's sealed archive, never
    /// caller-supplied strings or an independently supplied origin descriptor.
    fn disclosure_origin(&self, source_provenance: &RecoveryProvenance) -> HistoricalArchiveOrigin {
        let manifest = &self.archive.manifests[&self.manifest_digest];
        let node = &self.archive.nodes[&manifest.node_digest];
        HistoricalArchiveOrigin {
            root_manifest_digest: self.archive.root.clone(),
            root_capsule_id: self.archive.manifest().capsule_id.clone(),
            selected_manifest_digest: self.manifest_digest.clone(),
            selected_node_digest: manifest.node_digest.clone(),
            selected_capsule_id: manifest.capsule_id.clone(),
            selected_generation_id: node.generation_id.clone(),
            selected_profile_id: node.profile_id.clone(),
            selected_original_root: node.original_root.clone(),
            entry_id: self.id.clone(),
            role: self.entry().role.clone(),
            original_path: self.origin().into(),
            source_provenance: source_provenance.clone(),
        }
    }
    fn provenance(
        &self,
        template: &JournalTemplate,
        component_digest: String,
        rows: usize,
    ) -> RecoveryProvenance {
        let manifest = &self.archive.manifests[&self.manifest_digest];
        let node = &self.archive.nodes[&manifest.node_digest];
        RecoveryProvenance {
            profile_id: node.profile_id.clone(),
            checkpoint_id: manifest.capsule_id.clone(),
            bundle_digest: self.manifest_digest.clone(),
            component_id: self.id.clone(),
            kind: template.kind,
            component_digest,
            application_id: template.application_id,
            schema_version: template.schema_version,
            rows,
        }
    }
    fn materialize(&self) -> Result<tempfile::TempDir> {
        #[cfg(unix)]
        {
            use std::{
                io::Write,
                os::unix::fs::{OpenOptionsExt, PermissionsExt},
            };
            let directory = tempfile::Builder::new()
                .prefix("wholepact-capsule-journal-")
                .tempdir_in("/tmp")
                .map_err(|_| ArchiveError::Storage)?;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .map_err(|_| ArchiveError::Storage)?;
            let EntryPayload::Journal { files } = &self.entry().payload else {
                return Err(ArchiveError::Integrity);
            };
            for (suffix, object) in files {
                // Stale process-local WAL indices are archived evidence, never a
                // runtime input. READ_ONLY SQLite constructs a new private index.
                if suffix == "-shm" {
                    continue;
                }
                let path = directory.path().join(format!("journal.sqlite{suffix}"));
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(path)
                    .map_err(|_| ArchiveError::Storage)?;
                self.archive.visit_object(&object.digest, |_, chunk| {
                    file.write_all(chunk).map_err(|_| ArchiveError::Storage)
                })?;
                file.flush().map_err(|_| ArchiveError::Storage)?;
            }
            Ok(directory)
        }
        #[cfg(not(unix))]
        {
            Err(ArchiveError::Unsupported)
        }
    }
}
