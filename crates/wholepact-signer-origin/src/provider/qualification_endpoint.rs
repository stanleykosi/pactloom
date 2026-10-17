//! Synthetic current-process endpoint reporting only. No path or successful
//! report grants installed/native/account authority. The original consumer still
//! checks its old peer, fresh endpoint, exact Pair scope and all original clocks.
use crate::{Error, Result};
use std::{
    path::{Path, PathBuf},
    sync::{
        Mutex,
        mpsc::{self, Receiver, SyncSender},
    },
    time::{Duration, Instant},
};

/// One-use availability reporter. The finite signer facade retains it privately
/// through its actual read -> dormant -> reopened completion controller. It has
/// no Clone/serde implementation and cannot replace the original provider.
pub struct QualificationEndpointReporterV1 {
    sender: SyncSender<PathBuf>,
    process: (u32, u32),
}
pub(super) struct QualificationEndpointReceiverV1 {
    receiver: Mutex<Option<Receiver<PathBuf>>>,
    process: (u32, u32),
}
pub(super) fn pair() -> (QualificationEndpointReceiverV1, QualificationEndpointReporterV1) {
    let (sender, receiver) = mpsc::sync_channel(1);
    let process = current_process();
    (
        QualificationEndpointReceiverV1 {
            receiver: Mutex::new(Some(receiver)),
            process,
        },
        QualificationEndpointReporterV1 { sender, process },
    )
}
fn current_process() -> (u32, u32) {
    (std::process::id(), unsafe { libc::geteuid() })
}
fn require_process(expected: (u32, u32)) -> Result<()> {
    if expected != current_process() {
        Err(Error::SignerOriginUnavailable)
    } else {
        Ok(())
    }
}
fn require_locator(endpoint: &Path) -> Result<()> {
    let text = endpoint.to_str().ok_or(Error::InvalidData)?;
    if !endpoint.is_absolute() || text.is_empty() || text.len() > 4096 {
        return Err(Error::InvalidData);
    }
    Ok(())
}
impl QualificationEndpointReporterV1 {
    /// Consumes the sole report opportunity even if validation or delivery fails.
    /// Only endpoint availability is reported; the receiver creates no grant.
    pub fn publish(self, endpoint: &Path) -> Result<()> {
        let Self { sender, process } = self;
        require_process(process)?;
        require_locator(endpoint)?;
        sender
            .try_send(endpoint.to_path_buf())
            .map_err(|_| Error::SignerOriginUnavailable)
    }
}
impl QualificationEndpointReceiverV1 {
    pub(super) fn wait(&self, timeout: Duration) -> Result<PathBuf> {
        // Take before every check/wait. Timeout, drop, malformed data or a late
        // result is terminal. There is no second receiver or renewed wait.
        let receiver = self
            .receiver
            .lock()
            .map_err(|_| Error::Locked)?
            .take()
            .ok_or(Error::Conflict)?;
        require_process(self.process)?;
        let deadline = Instant::now().checked_add(timeout).ok_or(Error::Permission)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(Error::Permission)?;
        let endpoint = receiver
            .recv_timeout(remaining)
            .map_err(|_| Error::SignerOriginUnavailable)?;
        if Instant::now() >= deadline {
            return Err(Error::Permission);
        }
        require_process(self.process)?;
        require_locator(&endpoint)?;
        Ok(endpoint)
    }
}
