//! Synthetic byte-file checks only. These files are deliberately not wallets,
//! SQLCipher databases or accepted historical authentication evidence.
use super::*;
use std::{
    cell::Cell,
    os::unix::fs::{PermissionsExt, symlink},
    time::Duration,
};

fn write(root: &Path, name: &str, bytes: &[u8]) {
    fs::write(root.join(name), bytes).unwrap();
    fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
}
fn fixture(full: bool) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let profile = temporary.path().join("synthetic-profile");
    let archive = temporary.path().join("synthetic-archive");
    for root in [&profile, &archive] {
        fs::create_dir(root).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let profile_names = if full {
        PROFILE_NAMES
    } else {
        &["signer.lock", "account.wp", "authority.sqlite"]
    };
    let archive_names = if full {
        ARCHIVE_NAMES
    } else {
        &["signer.lock", "recovery.wp", "COMPLETE", "bundle.sqlite"]
    };
    for name in profile_names {
        write(&profile, name, b"synthetic-source-ciphertext-placeholder");
    }
    for name in archive_names {
        write(&archive, name, b"synthetic-archive-ciphertext-placeholder");
    }
    (temporary, profile, archive)
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}
fn tree(root: &Path) -> BTreeMap<String, (Vec<u8>, Stamp)> {
    read_inventory(root, root.ends_with("synthetic-archive"), deadline())
        .unwrap()
        .into_iter()
        .map(|(name, stamp)| {
            let bytes = fs::read(root.join(&name)).unwrap();
            (name, (bytes, stamp))
        })
        .collect()
}

#[test]
fn complete_inventory_capture_and_recheck_preserve_all_bytes_and_metadata() {
    let (_temporary, profile, archive) = fixture(true);
    let before = (tree(&profile), tree(&archive));
    let captured = RetainedSources::capture(&profile, &archive, deadline()).unwrap();
    let digest = captured.digest().to_owned();
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    captured.check_until(deadline()).unwrap();
    assert!(before == (tree(&profile), tree(&archive)));
    assert_eq!(captured.profile.files.len(), PROFILE_NAMES.len());
    assert_eq!(captured.archive.files.len(), ARCHIVE_NAMES.len());
    let second = RetainedSources::capture(&profile, &archive, deadline()).unwrap();
    assert_eq!(digest, second.digest());
}

#[test]
fn every_account_recipient_database_wal_shm_and_archive_file_is_rechecked() {
    for (in_archive, names) in [(false, PROFILE_NAMES), (true, ARCHIVE_NAMES)] {
        for name in names {
            let (_temporary, profile, archive) = fixture(true);
            let captured = RetainedSources::capture(&profile, &archive, deadline()).unwrap();
            let root = if in_archive { &archive } else { &profile };
            let mut bytes = fs::read(root.join(name)).unwrap();
            bytes[0] ^= 1;
            write(root, name, &bytes);
            let after_mutation = (tree(&profile), tree(&archive));
            assert!(
                captured.check_until(deadline()).is_err(),
                "unchecked file: {name}"
            );
            assert!(after_mutation == (tree(&profile), tree(&archive)));
        }
    }
}

#[test]
fn content_hash_is_checked_independently_of_metadata_stamps() {
    let (_temporary, profile, archive) = fixture(true);
    let mut captured = RetainedSources::capture(&profile, &archive, deadline()).unwrap();
    let name = "authority.sqlite-shm";
    let mut bytes = fs::read(profile.join(name)).unwrap();
    bytes[0] ^= 1;
    write(&profile, name, &bytes);
    // Test-only stamp substitution isolates the content comparison; production
    // stamps are immutable, and no OS timestamp or source metadata is repaired.
    captured.profile.files.get_mut(name).unwrap().stamp =
        Stamp::read(&fs::symlink_metadata(profile.join(name)).unwrap(), false).unwrap();
    captured.profile.check_metadata(deadline()).unwrap();
    assert!(captured.check_until(deadline()).is_err());
}

#[test]
fn identical_bytes_at_a_replaced_file_identity_are_refused() {
    let (_temporary, profile, archive) = fixture(true);
    let captured = RetainedSources::capture(&profile, &archive, deadline()).unwrap();
    let bytes = fs::read(profile.join("account.wp")).unwrap();
    fs::rename(
        profile.join("account.wp"),
        _temporary.path().join("old-synthetic-account"),
    )
    .unwrap();
    write(&profile, "account.wp", &bytes);
    assert!(captured.check_until(deadline()).is_err());
}

#[test]
fn root_replacement_and_source_file_removal_are_refused() {
    let (temporary, profile, archive) = fixture(false);
    let captured = RetainedSources::capture(&profile, &archive, deadline()).unwrap();
    fs::remove_file(archive.join("COMPLETE")).unwrap();
    assert!(captured.check_until(deadline()).is_err());
    drop(captured);
    write(&archive, "COMPLETE", b"synthetic-marker");
    let captured = RetainedSources::capture(&profile, &archive, deadline()).unwrap();
    fs::rename(&profile, temporary.path().join("old-synthetic-profile")).unwrap();
    fs::create_dir(&profile).unwrap();
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["signer.lock", "account.wp", "authority.sqlite"] {
        write(&profile, name, b"synthetic-source-ciphertext-placeholder");
    }
    assert!(captured.check_until(deadline()).is_err());
}

#[test]
fn optional_sidecar_absence_unknown_entries_and_missing_pairs_are_exact() {
    for (in_archive, name) in [
        (false, "authority.sqlite-wal"),
        (false, "authority.sqlite-shm"),
        (true, "bundle.sqlite-wal"),
        (true, "bundle.sqlite-shm"),
    ] {
        let (_temporary, profile, archive) = fixture(false);
        let captured = RetainedSources::capture(&profile, &archive, deadline()).unwrap();
        write(
            if in_archive { &archive } else { &profile },
            name,
            b"synthetic-late-sidecar",
        );
        assert!(captured.check_until(deadline()).is_err());
    }
    for name in [
        "unknown.wp",
        "authority.sqlite-journal",
        "recipient-record-key.wp",
        "viewing-wallet.sqlite-shm",
    ] {
        let (_temporary, profile, archive) = fixture(false);
        write(&profile, name, b"synthetic-unsupported-file");
        assert!(RetainedSources::capture(&profile, &archive, deadline()).is_err());
    }
}

#[test]
fn unsafe_permissions_links_symlinks_and_special_files_fail_closed() {
    let (temporary, profile, archive) = fixture(false);
    fs::set_permissions(
        profile.join("account.wp"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(RetainedSources::capture(&profile, &archive, deadline()).is_err());
    fs::set_permissions(
        profile.join("account.wp"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::hard_link(
        profile.join("account.wp"),
        temporary.path().join("synthetic-alias"),
    )
    .unwrap();
    assert!(RetainedSources::capture(&profile, &archive, deadline()).is_err());
    fs::remove_file(temporary.path().join("synthetic-alias")).unwrap();
    fs::remove_file(profile.join("account.wp")).unwrap();
    symlink(archive.join("recovery.wp"), profile.join("account.wp")).unwrap();
    assert!(RetainedSources::capture(&profile, &archive, deadline()).is_err());
    fs::remove_file(profile.join("account.wp")).unwrap();
    fs::create_dir(profile.join("account.wp")).unwrap();
    assert!(RetainedSources::capture(&profile, &archive, deadline()).is_err());
}

#[test]
fn per_file_and_combined_tree_limits_apply_before_unbounded_reads() {
    let (_temporary, profile, archive) = fixture(false);
    write(
        &profile,
        "account.wp",
        &vec![0x53; super::super::MAX_ACCOUNT + 1025],
    );
    assert!(RetainedSources::capture(&profile, &archive, deadline()).is_err());
    write(&profile, "account.wp", b"synthetic-account");
    let profile_bytes: u64 = read_inventory(&profile, false, deadline())
        .unwrap()
        .values()
        .map(|stamp| stamp.length)
        .sum();
    let archive_bytes: u64 = read_inventory(&archive, true, deadline())
        .unwrap()
        .values()
        .map(|stamp| stamp.length)
        .sum();
    let mut remaining = profile_bytes + archive_bytes - 1;
    let _source = SourceTree::capture(&profile, false, &mut remaining, deadline()).unwrap();
    assert!(SourceTree::capture(&archive, true, &mut remaining, deadline()).is_err());
}

#[test]
fn expired_open_and_recheck_do_not_renew_original_deadline() {
    let (_temporary, profile, archive) = fixture(false);
    let expired = Instant::now() - Duration::from_secs(1);
    assert!(matches!(
        RetainedSources::capture(&profile, &archive, expired),
        Err(Error::ReviewMismatch)
    ));
    let mut captured = RetainedSources::capture(&profile, &archive, deadline()).unwrap();
    captured.deadline = expired;
    assert!(matches!(
        captured.check_until(deadline()),
        Err(Error::ReviewMismatch)
    ));
}

#[test]
fn chunked_hash_bounds_every_read_and_checks_exact_eof() {
    let length = CHUNK_BYTES as u64 * 2 + 7;
    let mut largest = 0;
    let mut offsets = Vec::new();
    hash_until(length, deadline(), Instant::now, |buffer, offset| {
        largest = largest.max(buffer.len());
        offsets.push(offset);
        if offset == length {
            return Ok(0);
        }
        buffer.fill(0x53);
        Ok(buffer.len())
    })
    .unwrap();
    assert_eq!(largest, CHUNK_BYTES);
    assert_eq!(
        offsets,
        [0, CHUNK_BYTES as u64, 2 * CHUNK_BYTES as u64, length]
    );
    assert!(hash_until(0, deadline(), Instant::now, |_buffer, _offset| Ok(1)).is_err());
    assert!(hash_until(1, deadline(), Instant::now, |_buffer, _offset| Ok(0)).is_err());
}

#[test]
fn partial_reads_interruptions_and_final_eof_cannot_extend_deadline() {
    let start = Instant::now();
    for interrupted in [false, true] {
        let elapsed = Cell::new(Duration::ZERO);
        let calls = Cell::new(0usize);
        let result = hash_until(
            7,
            start + Duration::from_secs(3),
            || start + elapsed.get(),
            |buffer, _| {
                calls.set(calls.get() + 1);
                elapsed.set(elapsed.get() + Duration::from_secs(1));
                if interrupted {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    buffer[0] = 0x53;
                    Ok(1)
                }
            },
        );
        assert!(matches!(result, Err(Error::ReviewMismatch)));
        assert_eq!(calls.get(), 3);
    }
    let elapsed = Cell::new(Duration::ZERO);
    let result = hash_until(
        0,
        start + Duration::from_secs(1),
        || start + elapsed.get(),
        |_, _| {
            elapsed.set(Duration::from_secs(1));
            Ok(0)
        },
    );
    assert!(matches!(result, Err(Error::ReviewMismatch)));
}
