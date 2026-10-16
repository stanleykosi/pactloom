//! Exact endpoint preflight only. Ordinary files and symlinks, never sockets.
use super::*;

#[test]
fn quarantined_endpoint_reentry_accepts_only_exact_absent_original_basename() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let exact = root.join(QUARANTINED_INFORMATIONAL_SOCKET_BASENAME);
    assert_eq!(
        quarantined_reentry_socket_path(&root, &exact).unwrap(),
        exact
    );
    assert!(!exact.exists());
    for name in [
        "requests-a.sock",
        "requests-aaaaaaaaaaaaaaaaaaaaaaaa.sock",
        "other.sock",
        "../quarantined-history-v5.sock",
    ] {
        assert!(quarantined_reentry_socket_path(&root, &root.join(name)).is_err());
    }
    let other = tempfile::tempdir().unwrap();
    assert!(
        quarantined_reentry_socket_path(&root, &other.path().join(exact.file_name().unwrap()))
            .is_err()
    );
}

#[test]
fn quarantined_endpoint_reentry_never_removes_or_reuses_existing_entries() {
    use std::os::unix::fs::symlink;
    for kind in 0..3 {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let exact = root.join(QUARANTINED_INFORMATIONAL_SOCKET_BASENAME);
        let missing = root.join("missing-target");
        match kind {
            0 => std::fs::write(&exact, b"synthetic-conflicting-file").unwrap(),
            1 => symlink(&missing, &exact).unwrap(),
            _ => std::fs::create_dir(&exact).unwrap(),
        }
        assert!(quarantined_reentry_socket_path(&root, &exact).is_err());
        match kind {
            0 => assert_eq!(
                std::fs::read(&exact).unwrap(),
                b"synthetic-conflicting-file"
            ),
            1 => assert_eq!(std::fs::read_link(&exact).unwrap(), missing),
            _ => assert!(exact.is_dir()),
        }
    }
}

#[test]
fn quarantined_endpoint_reentry_refuses_aliased_missing_or_nonprivate_runtime_parent() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let original = root.join("original");
    std::fs::create_dir(&original).unwrap();
    std::fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = root.join("alias");
    symlink(&original, &alias).unwrap();
    let name = QUARANTINED_INFORMATIONAL_SOCKET_BASENAME;
    assert!(quarantined_reentry_socket_path(&alias, &alias.join(name)).is_err());
    let missing = root.join("missing");
    assert!(quarantined_reentry_socket_path(&missing, &missing.join(name)).is_err());
    std::fs::set_permissions(&original, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(quarantined_reentry_socket_path(&original, &original.join(name)).is_err());
}
