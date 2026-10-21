//! Denial-only observations around one bounded selected credential read.
//! The legacy reader remains unchanged. This private helper issues no purpose
//! permission and does not perform source/journal audits under filesystem I/O.
use super::*;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use zeroize::Zeroize;

pub(super) fn read_initial_owner_credential_v1(
    path: &Path,
    final_read: &wholepact_financial_coordinator_origin::SignerFinancialReadFinalV1,
) -> Result<Zeroizing<Vec<u8>>> {
    read_private_credential_checked_v1(path, || {
        final_read.check_current()?;
        Ok(())
    })
}

/// The private caller must bind its concrete genuine current Final. This hook
/// only denies; it never opens a source, issues a grant, or refreshes a clock.
/// Both present callers use only their nominal token's zero-wait check_current.
pub(super) fn read_private_credential_checked_v1(
    path: &Path,
    mut check: impl FnMut() -> Result<()>,
) -> Result<Zeroizing<Vec<u8>>> {
    check()?;
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::InvalidData);
    }
    let parent = path.parent().ok_or(Error::InvalidData)?;
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(|_| Error::InvalidData)?;
    check()?;
    let uid = unsafe { libc::geteuid() };
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != uid
        || parent_metadata.mode() & 0o077 != 0
    {
        return Err(Error::InvalidData);
    }
    check()?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error::InvalidData)?;
    check()?;
    let metadata = file.metadata().map_err(|_| Error::InvalidData)?;
    check()?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > MAX_CREDENTIAL as u64
    {
        return Err(Error::InvalidData);
    }
    // Keep the exact already-open no-follow file. Never reopen/replace a path
    // or retry an interrupted/partial credential attempt after any failure.
    read_bounded_once(&mut file, &mut check)
}

fn read_bounded_once(
    reader: &mut impl Read,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_CREDENTIAL + 1));
    let mut scratch = Zeroizing::new([0u8; 4096]);
    loop {
        let remaining = (MAX_CREDENTIAL + 1)
            .checked_sub(bytes.len())
            .ok_or(Error::InvalidData)?;
        if remaining == 0 {
            break;
        }
        let limit = remaining.min(scratch.len());
        check()?;
        let observed = reader.read(&mut scratch[..limit]);
        // Even an already-started read may finish after R. Observe before any
        // bytes are accepted and deny every later physical attempt. This is
        // not an atomic check+syscall or a promise to cancel a blocked syscall.
        check()?;
        let count = observed.map_err(|_| Error::InvalidData)?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&scratch[..count]);
        scratch.zeroize();
    }
    check()?;
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL {
        return Err(Error::InvalidData);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, io::Cursor};

    struct CountingReader<'a> {
        cursor: Cursor<Vec<u8>>,
        reads: &'a Cell<usize>,
        interrupt: bool,
    }
    impl Read for CountingReader<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            self.reads.set(self.reads.get() + 1);
            if self.interrupt {
                return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
            }
            self.cursor.read(output)
        }
    }

    #[test]
    fn coordinated_credential_read_denial_stops_after_the_first_physical_read() {
        let reads = Cell::new(0);
        let mut reader = CountingReader {
            cursor: Cursor::new(vec![0x51; 5000]),
            reads: &reads,
            interrupt: false,
        };
        let result = read_bounded_once(&mut reader, &mut || {
            if reads.get() == 0 {
                Ok(())
            } else {
                Err(Error::Locked)
            }
        });
        assert!(result.is_err());
        assert_eq!(reads.get(), 1);
    }

    #[test]
    fn coordinated_credential_read_is_bounded_and_never_retries_interrupted_io() {
        let reads = Cell::new(0);
        let mut reader = CountingReader {
            cursor: Cursor::new(vec![0x52; 5000]),
            reads: &reads,
            interrupt: true,
        };
        assert!(read_bounded_once(&mut reader, &mut || Ok(())).is_err());
        assert_eq!(reads.get(), 1);
        for length in [0, MAX_CREDENTIAL + 1] {
            assert!(
                read_bounded_once(&mut Cursor::new(vec![0x53; length]), &mut || Ok(())).is_err()
            );
        }
        let exact = read_bounded_once(&mut Cursor::new(vec![0x54; MAX_CREDENTIAL]), &mut || Ok(()))
            .unwrap();
        assert_eq!(exact.len(), MAX_CREDENTIAL);
    }
}
