//! Synthetic filesystem boundary tests; these do not establish native approval.
use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

fn private_directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[test]
fn exact_private_directory_allocates_new_bytes_without_overwrite() {
    let dir = private_directory();
    let path = dir.path().join("handoff.json");
    let target = ExactFileDestination::prepare(&path).unwrap();
    let mut file = target.allocate().unwrap();
    target.check_created(&file, 0).unwrap();
    file.write_all(b"synthetic inert handoff").unwrap();
    file.sync_all().unwrap();
    target.sync_parent().unwrap();
    target
        .check_created(&file, b"synthetic inert handoff".len() as u64)
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"synthetic inert handoff");
    assert!(ExactFileDestination::prepare(&path).is_err());
    assert!(target.allocate().is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"synthetic inert handoff");
}

#[test]
fn changed_directory_identity_cannot_redirect_allocation() {
    let dir = private_directory();
    let original = dir.path().join("reviewed");
    let replaced = dir.path().join("moved");
    std::fs::create_dir(&original).unwrap();
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = ExactFileDestination::prepare(&original.join("handoff.json")).unwrap();
    std::fs::rename(&original, &replaced).unwrap();
    std::fs::create_dir(&original).unwrap();
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(target.allocate().is_err());
    assert!(!original.join("handoff.json").exists());
    assert!(!replaced.join("handoff.json").exists());
}

#[test]
fn nonprivate_directory_and_existing_symlink_fail_closed() {
    let dir = private_directory();
    let path = dir.path().join("handoff.json");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(ExactFileDestination::prepare(&path).is_err());
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    symlink("nonexistent", &path).unwrap();
    assert!(ExactFileDestination::prepare(&path).is_err());
}

#[test]
fn file_replacement_or_hardlink_never_passes_postcreation_identity() {
    let dir = private_directory();
    let path = dir.path().join("handoff.json");
    let target = ExactFileDestination::prepare(&path).unwrap();
    let file = target.allocate().unwrap();
    std::fs::hard_link(&path, dir.path().join("linked")).unwrap();
    assert!(target.check_created(&file, 0).is_err());
    std::fs::rename(&path, dir.path().join("moved")).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    assert!(target.check_created(&file, 0).is_err());
    // This helper never cleans up an allocated or replaced file after failure.
    assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
    assert!(dir.path().join("moved").exists());
}

#[test]
fn distinct_paths_or_parent_identity_change_the_review_binding() {
    let dir = private_directory();
    let first = ExactFileDestination::prepare(&dir.path().join("first.json")).unwrap();
    let second = ExactFileDestination::prepare(&dir.path().join("second.json")).unwrap();
    assert_ne!(first.review_binding(), second.review_binding());
    assert!(ExactFileDestination::prepare(Path::new("relative.json")).is_err());
    assert!(ExactFileDestination::prepare(&dir.path().join("bad\nname")).is_err());
}
