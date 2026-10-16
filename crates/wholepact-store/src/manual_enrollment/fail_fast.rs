//! Contention policy only, never consent or construction authority.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::Duration;

#[derive(Clone, Copy)]
pub(crate) enum ManualPersistenceMode {
    Existing,
    FailFast,
}
impl ManualPersistenceMode {
    pub(crate) fn with_connection<T>(
        self,
        connection: &mut rusqlite::Connection,
        operation: impl FnOnce(&mut rusqlite::Connection) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Existing => operation(connection),
            Self::FailFast => with_zero_busy_timeout(connection, operation),
        }
    }
}

/// Called only while the caller owns this connection's mutex. The supported
/// stores use SQLite timeout policies, never caller-installed busy callbacks.
/// Capture the actual previous timeout; do not assume the factory's 5 seconds.
/// This limits lock contention, not synchronous SQLite/fsync/filesystem time.
fn with_zero_busy_timeout<T>(
    connection: &mut rusqlite::Connection,
    operation: impl FnOnce(&mut rusqlite::Connection) -> Result<T>,
) -> Result<T> {
    let milliseconds: u32 = connection.pragma_query_value(None, "busy_timeout", |r| r.get(0))?;
    // SQLite cannot recover an arbitrary custom busy callback. A zero value
    // does not distinguish such a callback from a known immediate policy, so
    // this dedicated adapter refuses it rather than silently replacing it.
    if milliseconds == 0 || milliseconds > i32::MAX as u32 {
        return Err(StoreError::RecoveryRequired);
    }
    let previous = Duration::from_millis(u64::from(milliseconds));
    // Catch only to restore the connection policy before resuming the same
    // unwind. No panic is converted into permission or a successful operation.
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        connection.busy_timeout(Duration::ZERO)?;
        operation(connection)
    }));
    let restored = connection.busy_timeout(previous);
    match (outcome, restored) {
        (Ok(result), Ok(())) => result,
        // This may follow a durable commit. Returning an error must preserve
        // the original claim/checkpoint uncertainty and never permit retry.
        (Ok(_), Err(error)) => Err(error.into()),
        (Err(payload), Ok(())) => resume_unwind(payload),
        // Do not suppress restoration failure during unwinding. This occurs
        // outside the caught unwind, so the held mutex is poisoned normally.
        // The stricter no-wait policy may remain; no wait is silently widened.
        (Err(_), Err(_)) => panic!("SQLite busy timeout restoration failed during unwind"),
    }
}

#[cfg(test)]
mod tests;
