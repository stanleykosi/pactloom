//! Explicit synthetic-only isolated installation owner. This is NOT a path,
//! environment override, native approval or production namespace trust root.
//! Every probe still uses the maintained no-follow/identity/lock implementation.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

/// Owns a fresh synthetic directory, or the exact preserved original reopened
/// by the synthetic-only bounded comparison route. Never a production locator
/// or native approval. Every probe retains this owner until its files close.
pub struct EphemeralWitnessInstallation {
    directory: DirectoryCustodyV2,
    identity: DirectoryStamp,
    preserved: Option<PreservedOriginalV2>,
}
// Only the original temporary owner can preserve custody. A reopened preserved
// root is never deleted by this storage owner; outer qualification cleanup owns it.
enum DirectoryCustodyV2 {
    Temporary(tempfile::TempDir),
    Preserved(PathBuf),
}
impl DirectoryCustodyV2 {
    fn path(&self) -> &Path {
        match self {
            Self::Temporary(directory) => directory.path(),
            Self::Preserved(path) => path,
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreservedOriginalV2 {
    version: u16,
    home_path: PathBuf,
    home: DirectoryStamp,
    root: DirectoryStamp,
    journals: DirectoryStamp,
    marker: PreservedMarkerV2,
    installation_id: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreservedMarkerV2 {
    device: u64,
    inode: u64,
    owner_uid: u32,
    length: u64,
}
fn preserved_descriptor(files: &InstallationFiles) -> Result<PreservedOriginalV2> {
    files.check_current()?;
    let marker = private_file(&files.marker)?;
    Ok(PreservedOriginalV2 {
        version: 2,
        home_path: files.probe.home_path.clone(),
        home: stamp(&private_directory(&files.probe.home)?),
        root: files.root_stamp.clone(),
        journals: files.journals_stamp.clone(),
        marker: PreservedMarkerV2 {
            device: marker.dev(),
            inode: marker.ino(),
            owner_uid: marker.uid(),
            length: marker.len(),
        },
        installation_id: files.instance_id.clone(),
    })
}
impl EphemeralWitnessInstallation {
    pub fn new() -> Result<Arc<Self>> {
        let directory = tempfile::Builder::new()
            .prefix("wholepact-synthetic-witness-installation-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .map_err(|_| E::Io)?;
        let held = open_directory_walk(directory.path())?;
        let identity = stamp(&home_metadata(&held)?);
        let this = Arc::new(Self {
            directory: DirectoryCustodyV2::Temporary(directory),
            identity,
            preserved: None,
        });
        let probe = this.probe()?;
        probe.require_absent()?;
        drop(probe);
        Ok(this)
    }

    /// Consumes the exclusive original synthetic owner only after every probe,
    /// native worker, credential-origin borrower and journal has drained. Returns
    /// bounded inert source comparison bytes, never a native or journal grant.
    /// The SAME original directory survives process/drop; outer cleanup owns it.
    pub fn preserve_original_for_process_exit_v2(self: Arc<Self>) -> Result<Vec<u8>> {
        if Arc::strong_count(&self) != 1 {
            return Err(E::UnsafePath);
        }
        let files = self.probe()?.open_existing()?;
        let descriptor = preserved_descriptor(&files)?;
        let bytes = serde_json::to_vec(&descriptor).map_err(|_| E::AuthenticationFailed)?;
        if bytes.len() > 16 * 1024 {
            return Err(E::AuthenticationFailed);
        }
        drop(files);
        let owner = Arc::try_unwrap(self).map_err(|_| E::UnsafePath)?;
        let DirectoryCustodyV2::Temporary(directory) = owner.directory else {
            return Err(E::UnsafePath);
        };
        if directory.path() != descriptor.home_path {
            return Err(E::SourceChanged);
        }
        let kept = directory.keep();
        if kept != descriptor.home_path {
            return Err(E::SourceChanged);
        }
        Ok(bytes)
    }

    /// Existing-original synthetic storage only. This never creates, repairs,
    /// copies, resets, changes HOME, imports keys or restores native approval.
    /// Every supplied claim is rechecked through the maintained nofollow/private
    /// owner/exclusion kernel and the exact original installation marker. The
    /// Authority layer must still authenticate full original encrypted history
    /// and enter its fresh native historical review before disclosure/serving.
    pub fn reopen_preserved_original_v2(bytes: &[u8]) -> Result<Arc<Self>> {
        if bytes.is_empty() || bytes.len() > 16 * 1024 {
            return Err(E::AuthenticationFailed);
        }
        let expected: PreservedOriginalV2 =
            serde_json::from_slice(bytes).map_err(|_| E::AuthenticationFailed)?;
        if expected.version != 2
            || !expected.home_path.is_absolute()
            || expected.home_path.as_os_str().as_bytes().len() > 4096
            || !expected
                .home_path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("wholepact-synthetic-witness-installation-"))
        {
            return Err(E::UnsafePath);
        }
        check_id(&expected.installation_id)?;
        let owner = Arc::new(Self {
            directory: DirectoryCustodyV2::Preserved(expected.home_path.clone()),
            identity: expected.home.clone(),
            preserved: Some(expected.clone()),
        });
        let files = owner.probe()?.open_existing()?;
        if preserved_descriptor(&files)? != expected {
            return Err(E::SourceChanged);
        }
        files.check_current()?;
        drop(files);
        Ok(owner)
    }

    pub fn probe(self: &Arc<Self>) -> Result<InstallationProbe> {
        let home_path = self.directory.path().to_path_buf();
        let home = open_directory_walk(&home_path)?;
        let actual = stamp(&home_metadata(&home)?);
        if actual != self.identity {
            return Err(E::SourceChanged);
        }
        home.try_lock().map_err(|_| E::UnsafePath)?;
        if let Some(expected) = &self.preserved {
            // Retain and recheck every original identity on EVERY later probe,
            // not only while parsing the inert selector. Hold the maintained
            // home exclusion continuously through the caller's open_existing.
            private_directory(&home)?;
            let root = open_at(&home, ROOT_NAME, libc::O_RDONLY | libc::O_DIRECTORY)?;
            if stamp(&private_directory(&root)?) != expected.root {
                return Err(E::SourceChanged);
            }
            root.try_lock().map_err(|_| E::UnsafePath)?;
            let journals = open_at(&root, "journals", libc::O_RDONLY | libc::O_DIRECTORY)?;
            if stamp(&private_directory(&journals)?) != expected.journals {
                return Err(E::SourceChanged);
            }
            journals.try_lock().map_err(|_| E::UnsafePath)?;
            let mut marker = open_at(&root, "installation.id", libc::O_RDONLY)?;
            let metadata = private_file(&marker)?;
            let actual = PreservedMarkerV2 {
                device: metadata.dev(),
                inode: metadata.ino(),
                owner_uid: metadata.uid(),
                length: metadata.len(),
            };
            let mut id = String::new();
            (&mut marker)
                .take(65)
                .read_to_string(&mut id)
                .map_err(|_| E::Io)?;
            if actual != expected.marker || id != expected.installation_id {
                return Err(E::SourceChanged);
            }
        }
        let probe = InstallationProbe {
            home_path,
            home,
            _ephemeral_qualification: Some(self.clone()),
        };
        probe.check_current()?;
        Ok(probe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn exact_ephemeral_owner_retains_files_and_preserves_create_once_locking() {
        let owner = EphemeralWitnessInstallation::new().unwrap();
        let root = owner.probe().unwrap().root_path();
        let home = root.parent().unwrap().to_path_buf();
        // The maintained private-key reader requires an exactly private parent,
        // independently of ambient umask; home-only probe checks are weaker.
        assert_eq!(fs::metadata(&home).unwrap().mode() & 0o7777, 0o700);
        let probe = owner.probe().unwrap();
        assert!(owner.probe().is_err());
        let files = probe.create_once(&"11".repeat(32)).unwrap();
        files.check_current().unwrap();
        assert!(owner.probe().is_err());
        let retained = Arc::downgrade(&owner);
        drop(owner);
        assert!(retained.upgrade().is_some());
        assert!(root.is_dir());
        files.check_current().unwrap();
        drop(files);
        assert!(retained.upgrade().is_none());
        assert!(!home.exists());
    }

    #[test]
    fn exact_ephemeral_installation_reopens_without_adopting_another_root() {
        let owner = EphemeralWitnessInstallation::new().unwrap();
        let files = owner
            .probe()
            .unwrap()
            .create_once(&"22".repeat(32))
            .unwrap();
        let root = files.root_path().to_path_buf();
        let stamp = files.root_stamp().clone();
        drop(files);
        let probe = owner.probe().unwrap();
        assert!(probe.require_absent().is_err());
        let files = probe.open_existing().unwrap();
        assert_eq!(files.root_path(), root);
        assert!(files.root_stamp() == &stamp);
        files.check_current().unwrap();
        // A second independently generated fixture remains distinct; the bounded
        // preserved-original route cannot substitute this new identity.
        let other = EphemeralWitnessInstallation::new().unwrap();
        assert_ne!(other.probe().unwrap().root_path(), root);
    }

    struct PreservedCleanup(PathBuf);
    impl Drop for PreservedCleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn preserved() -> (Vec<u8>, PreservedOriginalV2, PreservedCleanup) {
        let owner = EphemeralWitnessInstallation::new().unwrap();
        let files = owner
            .probe()
            .unwrap()
            .create_once(&"33".repeat(32))
            .unwrap();
        drop(files);
        let bytes = owner.preserve_original_for_process_exit_v2().unwrap();
        let descriptor: PreservedOriginalV2 = serde_json::from_slice(&bytes).unwrap();
        let cleanup = PreservedCleanup(descriptor.home_path.clone());
        (bytes, descriptor, cleanup)
    }
    #[test]
    fn preserved_original_reopens_same_identity_without_create_or_drop_cleanup() {
        let (bytes, expected, _cleanup) = preserved();
        let reopened = EphemeralWitnessInstallation::reopen_preserved_original_v2(&bytes).unwrap();
        let files = reopened.probe().unwrap().open_existing().unwrap();
        assert!(preserved_descriptor(&files).unwrap() == expected);
        drop(files);
        drop(reopened);
        assert!(expected.home_path.join(ROOT_NAME).is_dir());
    }
    #[test]
    fn preservation_requires_all_original_borrowers_and_probes_drained() {
        let owner = EphemeralWitnessInstallation::new().unwrap();
        let files = owner
            .probe()
            .unwrap()
            .create_once(&"44".repeat(32))
            .unwrap();
        assert!(
            owner
                .clone()
                .preserve_original_for_process_exit_v2()
                .is_err()
        );
        drop(files);
        let borrower = owner.clone();
        assert!(borrower.preserve_original_for_process_exit_v2().is_err());
        assert!(owner.probe().unwrap().open_existing().is_ok());
    }
    #[test]
    fn preserved_selector_rejects_unknown_duplicate_and_changed_identity_claims() {
        let (bytes, expected, _cleanup) = preserved();
        for field in ["home", "root", "journals"] {
            let mut value = serde_json::to_value(&expected).unwrap();
            value[field]["inode"] = serde_json::json!(0);
            assert!(
                EphemeralWitnessInstallation::reopen_preserved_original_v2(
                    &serde_json::to_vec(&value).unwrap()
                )
                .is_err()
            );
        }
        let mut value = serde_json::to_value(&expected).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(
            EphemeralWitnessInstallation::reopen_preserved_original_v2(
                &serde_json::to_vec(&value).unwrap()
            )
            .is_err()
        );
        let duplicate =
            String::from_utf8(bytes.clone())
                .unwrap()
                .replacen("{", "{\"version\":2,", 1);
        assert!(
            EphemeralWitnessInstallation::reopen_preserved_original_v2(duplicate.as_bytes())
                .is_err()
        );
        for field in ["installation_id", "version"] {
            let mut value = serde_json::to_value(&expected).unwrap();
            value[field] = if field == "version" {
                serde_json::json!(3)
            } else {
                serde_json::json!("55".repeat(32))
            };
            assert!(
                EphemeralWitnessInstallation::reopen_preserved_original_v2(
                    &serde_json::to_vec(&value).unwrap()
                )
                .is_err()
            );
        }
    }
    #[test]
    fn preserved_reopen_rejects_lock_nonprivate_home_and_symlink_substitution() {
        let (bytes, expected, _cleanup) = preserved();
        let reopened = EphemeralWitnessInstallation::reopen_preserved_original_v2(&bytes).unwrap();
        let held = reopened.probe().unwrap().open_existing().unwrap();
        assert!(EphemeralWitnessInstallation::reopen_preserved_original_v2(&bytes).is_err());
        drop(held);
        fs::set_permissions(&expected.home_path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(EphemeralWitnessInstallation::reopen_preserved_original_v2(&bytes).is_err());
        fs::set_permissions(&expected.home_path, fs::Permissions::from_mode(0o700)).unwrap();
        let root = expected.home_path.join(ROOT_NAME);
        let moved = expected.home_path.join("moved-original");
        fs::rename(&root, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &root).unwrap();
        assert!(EphemeralWitnessInstallation::reopen_preserved_original_v2(&bytes).is_err());
        assert!(reopened.probe().is_err());
    }
    #[test]
    fn preserved_owner_rejects_marker_replacement_after_reopen_before_next_probe() {
        let (bytes, expected, _cleanup) = preserved();
        let reopened = EphemeralWitnessInstallation::reopen_preserved_original_v2(&bytes).unwrap();
        let marker = expected.home_path.join(ROOT_NAME).join("installation.id");
        let moved = marker.with_extension("original");
        fs::rename(&marker, &moved).unwrap();
        let mut replacement = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&marker)
            .unwrap();
        replacement
            .write_all(expected.installation_id.as_bytes())
            .unwrap();
        drop(replacement);
        assert!(reopened.probe().is_err());
        assert!(EphemeralWitnessInstallation::reopen_preserved_original_v2(&bytes).is_err());
        fs::remove_file(&marker).unwrap();
        assert!(reopened.probe().is_err());
    }
    #[test]
    fn preserved_owner_rejects_replaced_root_or_journals_and_foreign_original() {
        for replace_journals in [false, true] {
            let (bytes, expected, _cleanup) = preserved();
            let reopened =
                EphemeralWitnessInstallation::reopen_preserved_original_v2(&bytes).unwrap();
            let selected = if replace_journals {
                expected.home_path.join(ROOT_NAME).join("journals")
            } else {
                expected.home_path.join(ROOT_NAME)
            };
            fs::rename(&selected, selected.with_extension("saved-original")).unwrap();
            fs::create_dir(&selected).unwrap();
            fs::set_permissions(&selected, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(reopened.probe().is_err());
            assert!(EphemeralWitnessInstallation::reopen_preserved_original_v2(&bytes).is_err());
        }
        let (_, mut expected, _original_cleanup) = preserved();
        let (_, foreign, _foreign_cleanup) = preserved();
        expected.home_path = foreign.home_path;
        let mixed = serde_json::to_vec(&expected).unwrap();
        assert!(EphemeralWitnessInstallation::reopen_preserved_original_v2(&mixed).is_err());
    }
}
