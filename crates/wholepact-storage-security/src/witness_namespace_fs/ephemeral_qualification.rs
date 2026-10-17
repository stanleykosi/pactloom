//! Explicit synthetic-only isolated installation owner. This is NOT a path,
//! environment override, native approval or production namespace trust root.
//! Every probe still uses the maintained no-follow/identity/lock implementation.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

/// Owns the sole fresh temporary directory it can ever probe. There is no input
/// path, raw identity, Clone/Deserialize or adoption/reopen-existing constructor.
/// Every returned probe retains this exact owner so its files outlive all uses.
pub struct EphemeralWitnessInstallation {
    directory: tempfile::TempDir,
    identity: DirectoryStamp,
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
            directory,
            identity,
        });
        let probe = this.probe()?;
        probe.require_absent()?;
        drop(probe);
        Ok(this)
    }

    pub fn probe(self: &Arc<Self>) -> Result<InstallationProbe> {
        let home_path = self.directory.path().to_path_buf();
        let home = open_directory_walk(&home_path)?;
        let actual = stamp(&home_metadata(&home)?);
        if actual != self.identity {
            return Err(E::SourceChanged);
        }
        home.try_lock().map_err(|_| E::UnsafePath)?;
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
        // A second independently generated fixture is distinct. No API accepts
        // the first root path or its immutable installation identity as input.
        let other = EphemeralWitnessInstallation::new().unwrap();
        assert_ne!(other.probe().unwrap().root_path(), root);
    }
}
