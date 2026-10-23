//! Actual first original19 opening for coordinated V3, not a completed-V3
//! importer. Only the distinct paired original input and Entry grant decrypt.
use super::*;
use crate::native_peer::PeerProcess;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wholepact_financial_coordinator_origin::{
    SignerV3SourceEntryFactsV1, SignerV3SourceEntryFinalV1, SignerV3SourceEntryInputV1,
    SignerV3SourceEntryPresentationV1, SignerV3SourceLifetimeV1, SignerV3SourceOpenedV1,
};

fn wall_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Locked)?
            .as_millis(),
    )
    .map_err(|_| Error::Locked)
}

fn entry_deadline(now: Instant, source: Instant) -> Result<Instant> {
    let result = source.min(
        now.checked_add(Duration::from_secs(120))
            .ok_or(Error::Locked)?,
    );
    if result <= now {
        return Err(Error::Locked);
    }
    Ok(result)
}

// Public file metadata only. No account, roster, credential or SQL content is
// read while selecting. The actual locked directory and immutable inventory
// are checked again after decrypt; journal interpretation is separately fenced.
fn public_files(root: &Path) -> Result<String> {
    let root_meta = std::fs::symlink_metadata(root)?;
    if !root_meta.is_dir() || root_meta.file_type().is_symlink() || root_meta.mode() & 0o077 != 0 {
        return Err(Error::InvalidData);
    }
    let mut files = BTreeMap::new();
    files.insert(
        "$root".to_owned(),
        serde_json::json!([
            root_meta.dev(),
            root_meta.ino(),
            root_meta.uid(),
            root_meta.gid(),
            root_meta.mode()
        ]),
    );
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::InvalidData)?;
        if matches!(
            name.as_str(),
            "signer.lock"
                | "authority.sqlite-wal"
                | "authority.sqlite-shm"
                | "authority.sqlite-journal"
        ) {
            continue;
        }
        let m = std::fs::symlink_metadata(entry.path())?;
        if !m.is_file() || m.file_type().is_symlink() || m.nlink() != 1 || m.mode() & 0o077 != 0 {
            return Err(Error::InvalidData);
        }
        let value = if name == JOURNAL {
            serde_json::json!([m.dev(), m.ino(), m.uid(), m.gid(), m.mode(), m.nlink()])
        } else {
            serde_json::json!([
                m.dev(),
                m.ino(),
                m.uid(),
                m.gid(),
                m.mode(),
                m.nlink(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec()
            ])
        };
        files.insert(name, value);
    }
    let encoded = serde_json::to_string(&files).map_err(|_| Error::InvalidData)?;
    if encoded.len() > 12 * 1024 {
        return Err(Error::InvalidData);
    }
    Ok(encoded)
}

pub(crate) struct PreparedCoordinatedV3SourceEntryV1 {
    facts: SignerV3SourceEntryFactsV1,
    original_source_deadline: Instant,
    original_entry_deadline: Instant,
}
pub(crate) struct PresentedCoordinatedV3SourceEntryV1 {
    prepared: PreparedCoordinatedV3SourceEntryV1,
    presentation: SignerV3SourceEntryPresentationV1,
}

// Observe only selected public metadata. The proposed display is an exact
// selection-bound field; it is NOT a place for a generated summary. The native
// review renders the complete authenticated presentation and its fixed notice.
// Only prepare calls this in production, after original peer/root/clock checks.
fn observe_selected_public_facts(
    root: &Path,
    facts: &mut SignerV3SourceEntryFactsV1,
    host_instance: &str,
    wall: u64,
    remaining: u64,
) -> Result<()> {
    facts.canonical_root = root.to_str().ok_or(Error::InvalidData)?.to_owned();
    facts.public_source_files_json = public_files(root)?;
    facts.original_host_process_instance = host_instance.to_owned();
    facts.reviewed_at_ms = wall;
    facts.expires_at_ms = wall.checked_add(remaining).ok_or(Error::Locked)?;
    facts.source_selection_digest = facts.calculate_source_selection_digest()?;
    facts.validate()?;
    Ok(())
}

impl PreparedCoordinatedV3SourceEntryV1 {
    /// Inputs are ordinary proposed selections. The original issuer supplies
    /// actor/channel provenance; this preparation cannot open any private data.
    pub(crate) fn prepare(
        root: &Path,
        mut facts: SignerV3SourceEntryFactsV1,
        host: &PeerProcess,
        original_source_deadline: Instant,
    ) -> Result<Self> {
        host.check_alive()?;
        require_canonical_existing_root(root)?;
        let monotonic = Instant::now();
        let wall = wall_ms()?;
        let source_wall = monotonic
            .checked_add(Duration::from_millis(
                facts
                    .source_expires_at_ms
                    .checked_sub(wall)
                    .filter(|n| *n > 0)
                    .ok_or(Error::Locked)?,
            ))
            .ok_or(Error::Locked)?;
        let original_source_deadline = original_source_deadline.min(source_wall);
        let original_entry_deadline = entry_deadline(monotonic, original_source_deadline)?;
        let remaining = u64::try_from(
            original_entry_deadline
                .checked_duration_since(monotonic)
                .ok_or(Error::Locked)?
                .as_millis(),
        )
        .map_err(|_| Error::Locked)?;
        if remaining == 0 {
            return Err(Error::Locked);
        }
        observe_selected_public_facts(root, &mut facts, host.instance(), wall, remaining)?;
        host.check_alive()?;
        Ok(Self {
            facts,
            original_source_deadline,
            original_entry_deadline,
        })
    }
    pub(crate) fn facts(&self) -> &SignerV3SourceEntryFactsV1 {
        &self.facts
    }
    pub(crate) fn original_source_deadline(&self) -> Instant {
        self.original_source_deadline
    }
    pub(crate) fn original_entry_deadline(&self) -> Instant {
        self.original_entry_deadline
    }
    pub(crate) fn freeze(
        self,
        presentation: SignerV3SourceEntryPresentationV1,
    ) -> Result<PresentedCoordinatedV3SourceEntryV1> {
        presentation.validate()?;
        if presentation.facts != self.facts {
            return Err(Error::ReviewMismatch);
        }
        Ok(PresentedCoordinatedV3SourceEntryV1 {
            prepared: self,
            presentation,
        })
    }
}

/// Same actual opened account, encrypted journal and selected original records.
/// No Clone/serde, private getter, receive/admission grant or historical importer.
/// Subsequent distinct PrepareRead must consume this owner inside this module.
pub(crate) struct CoordinatedOriginalDeliverySourceV1 {
    retained: RetainedBornManualRosterEnrollmentV2,
    original_commit: publication::BornManualRosterCommitV2,
    journal: Arc<SignerConsentJournal>,
    revision: Option<PreparedDeliveryJournalRevisionV3>,
    enrollment: crate::consent_journal::AccountEnrollmentRecord,
    manifest: crate::consent_journal::AcceptedManifestRecord,
    immutable: BTreeMap<String, FileRevisionV3>,
    witness: wholepact_authority::WitnessDisclosureDescriptor,
    lifetime: Arc<SignerV3SourceLifetimeV1>,
    opened: SignerV3SourceOpenedV1,
    host: PeerProcess,
    facts: SignerV3SourceEntryFactsV1,
    original_source_deadline: Instant,
}
impl CoordinatedOriginalDeliverySourceV1 {
    /// Cached observation of this actual opened owner; never a custody importer.
    pub(crate) fn opened_report(&self) -> &SignerV3SourceOpenedV1 {
        &self.opened
    }

    /// Cached original restriction only; not a private source/journal Read.
    pub(crate) fn check_retained_restriction(&self) -> Result<()> {
        self.lifetime.check_current()?;
        self.host.check_alive()?;
        if Instant::now() >= self.original_source_deadline
            || wall_ms()? >= self.facts.source_expires_at_ms
        {
            return Err(Error::Locked);
        }
        self.lifetime.check_current()?;
        Ok(())
    }
}
impl PresentedCoordinatedV3SourceEntryV1 {
    pub(crate) fn open(
        self,
        host: PeerProcess,
        input: SignerV3SourceEntryInputV1,
        final_action: SignerV3SourceEntryFinalV1,
    ) -> Result<CoordinatedOriginalDeliverySourceV1> {
        let facts = &self.prepared.facts;
        let root = Path::new(&facts.canonical_root);
        let check = || -> Result<()> {
            final_action.check_current()?;
            host.check_alive()?;
            if final_action.presentation() != &self.presentation
                || final_action.original_source_deadline() != self.prepared.original_source_deadline
                || final_action.original_entry_deadline() != self.prepared.original_entry_deadline
                || host.instance() != facts.original_host_process_instance
                || Instant::now() >= self.prepared.original_source_deadline
                || wall_ms()? >= facts.source_expires_at_ms
            {
                return Err(Error::ReviewMismatch);
            }
            final_action.check_current()?;
            Ok(())
        };
        check()?;
        require_canonical_existing_root(root)?;
        if public_files(root)? != facts.public_source_files_json {
            return Err(Error::ReviewMismatch);
        }
        check()?;
        let password = input.open(&final_action)?;
        check()?;
        let directory = PrivateDirectory::open_existing(root)?;
        check()?;
        if public_files(root)? != facts.public_source_files_json {
            return Err(Error::ReviewMismatch);
        }
        check()?;
        let encrypted = directory.read("account.wp", 512 * 1024)?;
        check()?;
        let account = Arc::new(active::open_for_coordinated_v3_source_entry_v1(
            directory,
            &password,
            &encrypted,
            &final_action,
        )?);
        drop(password);
        check()?;
        super::super::super::original(&account)?;
        check()?;
        super::super::super::roster_inventory(&account.directory)?;
        check()?;
        let retained = super::super::super::read_roster_retained(account.clone())?;
        check()?;
        retained.check()?;
        check()?;
        let original_commit = publication::read_commit(&retained)?;
        check()?;
        let witness = retained.disclosure()?;
        check()?;
        let genesis = &retained.record.account_record.genesis;
        let disclosure_json = serde_json::to_string(&witness).map_err(|_| Error::InvalidData)?;
        let disclosure_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:coordinated-original-financial-disclosure:v1",
            &witness,
        )
        .map_err(|_| Error::InvalidData)?;
        if genesis.identity.account_id != facts.account_id
            || retained
                .record
                .account_record
                .terms
                .signer
                .owner_certificate_digest
                != facts.owner_certificate_digest
            || disclosure_json != facts.witness_disclosure_json
            || disclosure_digest != facts.witness_disclosure_digest
        {
            return Err(Error::ReviewMismatch);
        }
        let source_owner = account.directory.signer_journal_source_owner()?;
        check()?;
        let journal = Arc::new(SignerConsentJournal::open_coordinated_v3_source_entry_v1(
            &root.join(JOURNAL),
            &DatabaseKey::from_bytes(*retained.journal_key),
            genesis,
            &source_owner,
            &final_action,
        )?);
        drop(source_owner);
        check()?;
        let (revision, enrollment, manifest) = journal.prepare_coordinated_v3_entry_revision(
            genesis,
            &facts.original_enrollment_ref,
            &facts.original_manifest_ref,
            &final_action,
        )?;
        check()?;
        let immutable = immutable_files(&retained)?;
        check()?;
        if public_files(root)? != facts.public_source_files_json
            || publication::read_commit(&retained)? != original_commit
        {
            return Err(Error::ReviewMismatch);
        }
        check()?;
        retained.check()?;
        check()?;
        if immutable_files(&retained)? != immutable {
            return Err(Error::ReviewMismatch);
        }
        check()?;
        let source_identity_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:coordinated-original-delivery-source:v1",
            &(
                &self.presentation.presentation_digest,
                &retained.record,
                &original_commit,
                genesis,
                enrollment.reference(),
                manifest.reference(),
                hex::encode(crate::vault::random::<32>()?),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        check()?;
        let opened = SignerV3SourceOpenedV1 {
            entry_presentation_digest: self.presentation.presentation_digest.clone(),
            source_identity_digest,
        };
        let lifetime = Arc::new(final_action.into_original_custody_lifetime()?);
        Ok(CoordinatedOriginalDeliverySourceV1 {
            retained,
            original_commit,
            journal,
            revision: Some(revision),
            enrollment,
            manifest,
            immutable,
            witness,
            lifetime,
            opened,
            host,
            facts: self.prepared.facts,
            original_source_deadline: self.prepared.original_source_deadline,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v3_entry_own_review_is_capped_by_exact_original_source() {
        let now = Instant::now();
        let short = now + Duration::from_secs(1);
        assert!(entry_deadline(now, short).is_ok_and(|actual| actual == short));
        assert!(entry_deadline(now, now + Duration::from_secs(900))
            .is_ok_and(|actual| actual == now + Duration::from_secs(120)));
        assert!(entry_deadline(now, now).is_err());
    }
}

#[path = "coordinated_source_entry_v1/coordinated_pairing_v1.rs"]
mod coordinated_pairing_v1;
pub(crate) use coordinated_pairing_v1::{CoordinatedSourcePairingV1, CoordinatedSourceReceiptBindingV1, CoordinatedFinancialRoleTransportV1};

#[path = "coordinated_source_entry_v1/coordinated_receipts_v1.rs"]
mod coordinated_receipts_v1;
pub(crate) use coordinated_receipts_v1::{CoordinatedEnrollmentReviewV1, CoordinatedManifestReviewV1, CoordinatedPreconstructionReadyV1, CoordinatedRestrictedReceiptV1};

#[path = "coordinated_source_entry_v1/coordinated_redisclosure_v1.rs"]
mod coordinated_redisclosure_v1;
pub(crate) use coordinated_redisclosure_v1::{CoordinatedRedisclosureReadV1,CoordinatedRediscloseV1,CoordinatedRedisclosedSourceV1};

#[path = "coordinated_source_entry_v1/coordinated_delivery_source_v1.rs"]
mod coordinated_delivery_source_v1;
pub(crate) use coordinated_delivery_source_v1::{CoordinatedPreparingDeliverySourceV1,CoordinatedPreparedDeliverySourceV1};

#[cfg(test)]
mod initial_entry_display_regression {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use wholepact_financial_coordinator_origin::{SignerContinueRoleV1,SignerV3SourceEntrySelectionV1};

    #[test]
    fn observed_public_facts_preserve_both_owner_proposals_and_bind_metadata() {
        for role in [SignerContinueRoleV1::Signer1,SignerContinueRoleV1::Signer2] {
            let directory=tempfile::tempdir().unwrap();
            std::fs::set_permissions(directory.path(),std::fs::Permissions::from_mode(0o700)).unwrap();
            let path=directory.path().join("public-synthetic-metadata");
            std::fs::write(&path,b"public synthetic metadata only").unwrap();
            std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();
            let hash=match role {SignerContinueRoleV1::Signer1=>"ab",SignerContinueRoleV1::Signer2=>"ef"}.repeat(32);
            let selection=SignerV3SourceEntrySelectionV1 {
                canonical_root:directory.path().to_str().unwrap().into(),account_id:hash.clone(),
                original_enrollment_ref:hash.clone(),original_manifest_ref:hash.clone(),owner_certificate_digest:hash.clone(),
                witness_disclosure_json:"{}".into(),witness_disclosure_digest:hash.clone(),session_digest:hash,
                display:"Exact selected public proposal; no source unlock approved.".into(),source_expires_at_ms:300_000,
            };
            selection.validate().unwrap();
            let mut facts=selection.proposed_facts(&"cd".repeat(32)).unwrap();
            observe_selected_public_facts(directory.path(),&mut facts,&"cd".repeat(32),1_000,120_000).unwrap();
            facts.validate().unwrap();
            let selected=serde_json::to_value(&selection).unwrap();let observed=serde_json::to_value(&facts).unwrap();
            for field in ["canonical_root","account_id","original_enrollment_ref","original_manifest_ref","owner_certificate_digest","witness_disclosure_json","witness_disclosure_digest","session_digest","display","source_expires_at_ms"] {
                assert_eq!(selected[field],observed[field],"{field}");
            }
            assert!(facts.public_source_files_json.contains("public-synthetic-metadata"));
            assert_eq!(facts.original_host_process_instance,"cd".repeat(32));
            assert_eq!(facts.reviewed_at_ms,1_000);assert_eq!(facts.expires_at_ms,121_000);
            assert_eq!(facts.source_selection_digest,facts.calculate_source_selection_digest().unwrap());
            let mut changed=facts.clone();changed.public_source_files_json="{}".into();
            assert_ne!(changed.calculate_source_selection_digest().unwrap(),facts.source_selection_digest);
            assert!(changed.validate().is_err());
        }
    }
}
