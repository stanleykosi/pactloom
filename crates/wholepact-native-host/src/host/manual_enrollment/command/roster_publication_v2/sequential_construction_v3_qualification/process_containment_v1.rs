//! Test-only process-local dump restriction and fixed policy classification.
//! No sysctl, signal-policy, trust,
//! system-wide security setting, or resource limit is changed here. The exact
//! disposable CI invocation supplies inherited RLIMIT_CORE=0 before entry.
use std::{
    fs::OpenOptions,
    io::{self, Read},
    os::unix::fs::OpenOptionsExt,
};

const MAX_CORE_PATTERN_BYTES: usize = 4096;

fn core_limit_is_zero(limit: Option<libc::rlim_t>) -> bool {
    limit == Some(0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CoreCollectorV1 {
    File,
    Pipe,
    Unknown,
}

fn classify_core_pattern(bytes: &[u8]) -> CoreCollectorV1 {
    if bytes.is_empty() || bytes.len() > MAX_CORE_PATTERN_BYTES || bytes.contains(&0) {
        return CoreCollectorV1::Unknown;
    }
    let Ok(pattern) = std::str::from_utf8(bytes) else {
        return CoreCollectorV1::Unknown;
    };
    let pattern = pattern.strip_suffix('\n').unwrap_or(pattern);
    // Classify conservatively, including a pipe preceded by whitespace. Never
    // disclose the actual pattern or a potential collector's command arguments.
    let pattern = pattern.trim();
    if pattern.is_empty() || pattern.contains(['\r', '\n']) {
        CoreCollectorV1::Unknown
    } else if pattern.starts_with('|') {
        CoreCollectorV1::Pipe
    } else {
        CoreCollectorV1::File
    }
}

pub(super) fn require_inherited_core_policy() -> io::Result<CoreCollectorV1> {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::zeroed();
    let actual = if unsafe { libc::getrlimit(libc::RLIMIT_CORE, limit.as_mut_ptr()) } == 0 {
        Some(unsafe { limit.assume_init() }.rlim_cur)
    } else {
        None
    };
    if !core_limit_is_zero(actual) {
        return Err(io::Error::other(
            "synthetic inherited core limit unavailable or nonzero",
        ));
    }
    // RLIMIT_CORE=0 does not establish absence of piped collector crash copies.
    // This expressly authorized disposable run uses only fresh synthetic data
    // and permits its default collector. Read this fixed policy solely for safe
    // classification; never inspect a core or collector contents. No sysctl change.
    let pattern = (|| -> io::Result<Vec<u8>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/proc/sys/kernel/core_pattern")?;
        let mut bytes = Vec::new();
        file.take((MAX_CORE_PATTERN_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    })();
    Ok(pattern.as_ref().map_or(CoreCollectorV1::Unknown, |bytes| {
        classify_core_pattern(bytes)
    }))
}

pub(super) fn require_and_report_core_policy() -> io::Result<()> {
    let collector = require_inherited_core_policy()?;
    // Do not change dumpability: actual IPC provider attestation may read
    // ptrace-gated peer metadata. This synthetic-only disposable run keeps the
    // inherited core limit and platform collector, not a crash-copy guarantee.
    eprintln!(
        "[JOINED_CORE_POLICY inherited_limit=Zero collector={collector:?} process_dumpability=Unchanged crash_copy_absence_verified=false]"
    );
    Ok(())
}

#[cfg(test)]
mod pure_tests {
    use super::*;
    #[test]
    fn pure_core_limit_requires_known_zero() {
        assert!(core_limit_is_zero(Some(0)));
        assert!(!core_limit_is_zero(None));
        assert!(!core_limit_is_zero(Some(1)));
        assert!(!core_limit_is_zero(Some(libc::RLIM_INFINITY)));
    }
    #[test]
    fn pure_core_route_has_only_file_pipe_or_unknown_classification() {
        assert_eq!(classify_core_pattern(b"core\n"), CoreCollectorV1::File);
        assert_eq!(
            classify_core_pattern(b"/tmp/core.%p"),
            CoreCollectorV1::File
        );
        assert_eq!(
            classify_core_pattern(b"|collector %p\n"),
            CoreCollectorV1::Pipe
        );
        assert_eq!(
            classify_core_pattern(b"  |collector"),
            CoreCollectorV1::Pipe
        );
        for invalid in [b"".as_slice(), b"\xff", b"core\0", b"core\nextra"] {
            assert_eq!(classify_core_pattern(invalid), CoreCollectorV1::Unknown);
        }
        assert_eq!(
            classify_core_pattern(&vec![b'x'; MAX_CORE_PATTERN_BYTES + 1]),
            CoreCollectorV1::Unknown
        );
    }
}
