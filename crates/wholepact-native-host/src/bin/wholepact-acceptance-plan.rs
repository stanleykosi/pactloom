//! Read-only plan emitter. No runtime, private journal, terminal, provider,
//! socket, signer, proof, subprocess or financial operation is reachable here.
use clap::Parser;
use serde::Serialize;
use std::{
    fs::File,
    io::Read,
    path::{Component, Path, PathBuf},
};
use wholepact_core::joined_acceptance::{self, MAX_CONFIG_BYTES};

#[derive(Parser)]
#[command(
    about = "Validate a metadata-only ordinary two-owner itinerary; never execute or qualify it"
)]
struct Args {
    /// Explicit planning-only acknowledgement. There is no execution mode.
    #[arg(long, required = true)]
    dry_run: bool,
    /// Bounded metadata worksheet, never a runtime/private source configuration.
    #[arg(long)]
    config: PathBuf,
    /// Local checkout for fixed source-file/entry-point presence checks only.
    #[arg(long)]
    source_root: PathBuf,
    /// Optional earlier worksheet; every recorded original must remain unchanged.
    #[arg(long)]
    prior_config: Option<PathBuf>,
}

#[derive(Serialize)]
struct SourcePresence {
    source: &'static str,
    entry_point: &'static str,
    status: &'static str,
}
#[derive(Serialize)]
struct Report {
    plan: joined_acceptance::Plan,
    source_inventory: Vec<SourcePresence>,
    source_presence_is_not: &'static str,
}

// Resolve every component under held directory descriptors. O_NOFOLLOW applies
// to each individual open, so replacing an ancestor cannot redirect a later read.
#[cfg(target_os = "linux")]
fn child(parent: &File, name: &std::ffi::OsStr, directory: bool) -> Result<File, &'static str> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    };
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| "Invalid local file name")?;
    let mut flags = libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NOCTTY;
    if directory {
        flags |= libc::O_DIRECTORY;
    }
    // SAFETY: parent owns a live descriptor and name is NUL-terminated. This
    // metadata-only open never invokes a device/TTY open handler and never
    // creates/modifies a file. The returned descriptor is checked.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err("Cannot open unlinked local metadata/source path");
    }
    // SAFETY: successful openat returned a new, uniquely owned file descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}
#[cfg(not(target_os = "linux"))]
fn child(_: &File, _: &std::ffi::OsStr, _: bool) -> Result<File, &'static str> {
    Err("Descriptor-relative planner source reads require a qualified Linux build")
}
fn open_directory(path: &Path) -> Result<File, &'static str> {
    let mut current = File::open(if path.is_absolute() { "/" } else { "." })
        .map_err(|_| "Cannot open source directory")?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => (),
            Component::Normal(name) => current = child(&current, name, true)?,
            Component::ParentDir => current = child(&current, std::ffi::OsStr::new(".."), true)?,
            Component::Prefix(_) => return Err("Unsupported source path"),
        }
    }
    Ok(current)
}
#[cfg(target_os = "linux")]
fn read_file(file: File, limit: usize) -> Result<Vec<u8>, &'static str> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let metadata = file
        .metadata()
        .map_err(|_| "Cannot inspect pinned metadata/source file")?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("Expected bounded regular metadata/source file");
    }
    // O_PATH above pins the inode without opening a device. Only after fstat
    // proves it is regular, reopen that held inode via the kernel's fd link.
    // No user-supplied symlink or substituted pathname is followed here.
    let reader = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|_| "Cannot read pinned regular metadata/source file")?;
    let opened = reader
        .metadata()
        .map_err(|_| "Cannot verify reopened regular file")?;
    if !opened.is_file()
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.len() > limit as u64
    {
        return Err("Pinned regular file changed unexpectedly");
    }
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read bounded metadata/source file")?;
    if bytes.len() > limit {
        return Err("Metadata/source file exceeded read bound");
    }
    Ok(bytes)
}
#[cfg(not(target_os = "linux"))]
fn read_file(_: File, _: usize) -> Result<Vec<u8>, &'static str> {
    Err("Pinned regular-file reads require a qualified Linux build")
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
    let parent = open_directory(path.parent().ok_or("Missing parent directory")?)?;
    let file = child(&parent, path.file_name().ok_or("Missing file name")?, false)?;
    read_file(file, limit)
}
fn source_present(root: &Path, relative: &str, marker: &str) -> bool {
    let Ok(mut directory) = open_directory(root) else {
        return false;
    };
    let mut components = Path::new(relative).components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return false;
        };
        if components.peek().is_none() {
            return child(&directory, name, false)
                .ok()
                .and_then(|file| read_file(file, 2 * 1024 * 1024).ok())
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .is_some_and(|source| source.contains(marker));
        }
        let Ok(next) = child(&directory, name, true) else {
            return false;
        };
        directory = next;
    }
    false
}

fn run(args: Args) -> Result<bool, Box<dyn std::error::Error>> {
    if !args.dry_run {
        return Err("Only explicit dry-run planning is supported".into());
    }
    let config = joined_acceptance::parse_config(&read_bounded(&args.config, MAX_CONFIG_BYTES)?)?;
    if let Some(path) = args.prior_config {
        let prior = joined_acceptance::parse_config(&read_bounded(&path, MAX_CONFIG_BYTES)?)?;
        joined_acceptance::preserve_originals(&prior, &config)?;
    }
    let plan = joined_acceptance::plan(&config);
    let source_inventory: Vec<_> = plan
        .stages
        .iter()
        .map(|stage| SourcePresence {
            source: stage.source,
            entry_point: stage.entry_point,
            status: if source_present(&args.source_root, stage.source, stage.entry_point) {
                "source_marker_present_not_qualified"
            } else {
                "source_gap_missing_unreadable_or_marker_absent"
            },
        })
        .collect();
    let source_gap = source_inventory
        .iter()
        .any(|source| source.status.starts_with("source_gap"));
    let report = Report {
        plan,
        source_inventory,
        source_presence_is_not:
            "implementation_correctness_authenticity_build_evidence_or_runtime_qualification",
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(source_gap)
}
fn main() {
    let args = Args::parse();
    match run(args) {
        Ok(false) => (), // Shape/presence only, never financial acceptance.
        Ok(true) => std::process::exit(3),
        Err(error) => {
            eprintln!("wholepact-acceptance-plan: {error}");
            std::process::exit(2);
        }
    }
}
