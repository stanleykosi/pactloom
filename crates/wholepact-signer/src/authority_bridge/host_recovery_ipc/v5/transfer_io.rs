//! Dedicated V5 bounded-transfer transport. Legacy IPC read/write helpers retain
//! their existing limits and behavior. This adapter never renews a transfer's
//! absolute deadline, including between partial writes or for its final newline.
use crate::{
    authority_bridge::{BridgeError, Result},
    native_peer::PeerProcess,
};
use serde::Serialize;
use std::{
    io::{self, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// Entire encoded wire frame, including the terminating newline. This is one
/// byte stricter than the legacy JSON-only sender limit, which is unchanged.
pub(crate) const FRAME_LIMIT: usize = 128 * 1024;
const WRITE_CALL_LIMIT: Duration = Duration::from_secs(2);

pub(crate) fn require_before_deadline(deadline: Instant) -> Result<()> {
    remaining_at(deadline, Instant::now()).map(|_| ())
}

fn remaining_at(deadline: Instant, now: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|duration| !duration.is_zero())
        .ok_or(BridgeError::Permission)
}

pub(crate) fn read_frame_until(
    stream: &UnixStream,
    peer: &PeerProcess,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>> {
    require_before_deadline(deadline)?;
    let frame = wholepact_signer_origin::framing::read_frame_capped_until(
        stream,
        peer,
        FRAME_LIMIT,
        deadline,
    )
    .map_err(|error| match error {
        wholepact_signer_origin::Error::Limit => BridgeError::Limit,
        _ => BridgeError::Ipc,
    })?;
    require_before_deadline(deadline)?;
    Ok(frame)
}

pub(crate) fn write_frame_until<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    deadline: Instant,
) -> Result<()> {
    require_before_deadline(deadline)?;
    let bytes = encode_frame(value)?;
    require_before_deadline(deadline)?;
    write_bytes_until(&bytes, deadline, Instant::now, |pending, timeout| {
        stream.set_write_timeout(Some(timeout))?;
        stream.write(pending)
    })
    // UnixStream is unbuffered: there is no additional flush work. In particular,
    // a new write_all/flush timeout must never extend the original deadline.
}

/// Actual partial-write loop, also exercised with a deterministic clock and
/// byte sink in pure tests. Every successful syscall, even the last newline,
/// must return before the original deadline. Interruptions consume that budget.
fn write_bytes_until(
    bytes: &[u8],
    deadline: Instant,
    mut now: impl FnMut() -> Instant,
    mut write: impl FnMut(&[u8], Duration) -> io::Result<usize>,
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > FRAME_LIMIT || bytes.last() != Some(&b'\n') {
        return Err(BridgeError::Limit);
    }
    let mut offset = 0usize;
    while offset < bytes.len() {
        let timeout = remaining_at(deadline, now())?.min(WRITE_CALL_LIMIT);
        let result = write(&bytes[offset..], timeout);
        remaining_at(deadline, now())?;
        match result {
            Ok(0) => return Err(BridgeError::Ipc),
            Ok(written) if written <= bytes.len() - offset => {
                offset = offset.checked_add(written).ok_or(BridgeError::Limit)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            _ => return Err(BridgeError::Ipc),
        }
    }
    remaining_at(deadline, now())?;
    Ok(())
}

struct BoundedFrame {
    bytes: Zeroizing<Vec<u8>>,
    limit_hit: bool,
}
impl Write for BoundedFrame {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let len = self.bytes.len().checked_add(bytes.len());
        if len.is_none_or(|len| len >= FRAME_LIMIT) {
            self.limit_hit = true;
            return Err(io::Error::other("bounded transfer frame limit"));
        }
        // Capacity was reserved once, before serialization. A malicious or
        // oversized value cannot make serde grow an unchecked temporary Vec.
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_frame<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let mut buffer = BoundedFrame {
        bytes: Zeroizing::new(Vec::new()),
        limit_hit: false,
    };
    buffer
        .bytes
        .try_reserve_exact(FRAME_LIMIT)
        .map_err(|_| BridgeError::Limit)?;
    if serde_json::to_writer(&mut buffer, value).is_err() {
        return Err(if buffer.limit_hit {
            BridgeError::Limit
        } else {
            BridgeError::Ipc
        });
    }
    buffer.bytes.push(b'\n');
    Ok(buffer.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn encoded_frame_cap_includes_newline_and_never_accepts_oversize() {
        let exact = "x".repeat(FRAME_LIMIT - 3); // JSON quotes and newline.
        let bytes = encode_frame(&exact).unwrap();
        assert_eq!(bytes.len(), FRAME_LIMIT);
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert!(matches!(
            encode_frame(&(exact + "x")),
            Err(BridgeError::Limit)
        ));
        assert_eq!(
            &**encode_frame(&serde_json::Value::Null).unwrap(),
            b"null\n"
        );
    }

    #[test]
    fn partial_writes_share_deadline_and_include_last_newline() {
        let start = Instant::now();
        let deadline = start + Duration::from_secs(3);
        let elapsed = Cell::new(Duration::ZERO);
        let mut sent = Vec::new();
        let mut timeouts = Vec::new();
        write_bytes_until(
            b"{}\n",
            deadline,
            || start + elapsed.get(),
            |bytes, timeout| {
                timeouts.push(timeout);
                sent.push(bytes[0]);
                elapsed.set(elapsed.get() + Duration::from_millis(600));
                Ok(1)
            },
        )
        .unwrap();
        assert_eq!(sent, b"{}\n");
        assert_eq!(
            timeouts,
            [
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_millis(1800)
            ]
        );
    }

    #[test]
    fn successful_final_write_at_deadline_still_refuses() {
        let start = Instant::now();
        let deadline = start + Duration::from_secs(1);
        let clock = Cell::new(start);
        let mut sent = Vec::new();
        let result = write_bytes_until(
            b"{}\n",
            deadline,
            || clock.get(),
            |bytes, timeout| {
                assert_eq!(timeout, Duration::from_secs(1));
                sent.extend_from_slice(bytes);
                clock.set(deadline);
                Ok(bytes.len())
            },
        );
        assert_eq!(sent, b"{}\n");
        assert!(matches!(result, Err(BridgeError::Permission)));
    }

    #[test]
    fn expired_budget_never_invokes_writer_and_interrupt_does_not_renew_it() {
        let start = Instant::now();
        assert!(
            write_bytes_until(b"{}\n", start, || start, |_, _| panic!("expired writer")).is_err()
        );
        let deadline = start + Duration::from_secs(1);
        let clock = Cell::new(start);
        let mut calls = 0;
        let result = write_bytes_until(
            b"{}\n",
            deadline,
            || clock.get(),
            |_, _| {
                calls += 1;
                clock.set(deadline);
                Err(io::ErrorKind::Interrupted.into())
            },
        );
        assert!(matches!(result, Err(BridgeError::Permission)));
        assert_eq!(calls, 1);
    }

    #[test]
    fn zero_and_impossible_write_lengths_refuse() {
        let start = Instant::now();
        let deadline = start + Duration::from_secs(1);
        for written in [0, 4] {
            assert!(matches!(
                write_bytes_until(b"{}\n", deadline, || start, |_, _| Ok(written)),
                Err(BridgeError::Ipc)
            ));
        }
    }
}
