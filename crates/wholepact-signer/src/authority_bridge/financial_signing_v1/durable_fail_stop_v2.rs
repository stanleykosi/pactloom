//! Opt-in qualification denial only. This can stop one actual operation after
//! its Started commit; it cannot create permission, a result, or a retry path.
use std::sync::{OnceLock, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use crate::authority_bridge::{BridgeError, Result};

struct ArmedStartedStop {
    account: String,
    authorization: String,
    outer_deadline: Instant,
    reached: AtomicBool,
}
static ARMED: OnceLock<ArmedStartedStop> = OnceLock::new();

pub(crate) fn arm_durable_financial_started_fail_stop_v2(
    expected_account: &str,
    expected_authorization: &str,
    outer_deadline: Instant,
) -> crate::Result<()> {
    crate::authority_bridge::born_history_ipc::hash(expected_account)
        .map_err(|_| crate::Error::InvalidData)?;
    if expected_authorization.is_empty() || expected_authorization.len() > 256
        || !expected_authorization.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_:".contains(&b))
        || Instant::now() >= outer_deadline
    { return Err(crate::Error::InvalidData); }
    ARMED.set(ArmedStartedStop {
        account: expected_account.to_owned(), authorization: expected_authorization.to_owned(),
        outer_deadline, reached: AtomicBool::new(false),
    }).map_err(|_| crate::Error::Uncertain)
}

pub(super) fn after_started_commit(
    actual_account: &str,
    actual_authorization: &str,
    original_deadline: Instant,
) -> Result<()> {
    let Some(armed) = ARMED.get() else { return Ok(()); };
    if armed.account != actual_account || armed.authorization != actual_authorization {
        return Err(BridgeError::Binding);
    }
    if armed.reached.swap(true, Ordering::AcqRel) { return Err(BridgeError::Uncertain); }
    let deadline = armed.outer_deadline.min(original_deadline);
    if Instant::now() >= deadline { return Err(BridgeError::Uncertain); }
    use std::io::Write;
    {
        let mut stderr = std::io::stderr().lock();
        if stderr.write_all(b"DURABLE_STARTED_COMMITTED_BEFORE_KEY_USE_V2\n").is_err()
            || stderr.flush().is_err()
        { return Err(BridgeError::Uncertain); }
    }
    // The owning supervisor kills/reaps this exact child. If it fails to do so,
    // the original/outer cutoff refuses permanently: never proceed to the key.
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        std::thread::park_timeout(remaining.min(Duration::from_millis(25)));
    }
    Err(BridgeError::Uncertain)
}
