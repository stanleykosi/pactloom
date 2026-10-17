//! Exact dispatch review while protected wallet transactions remain held.
//! No blocking terminal-lock or TTY read may outlive the original observation.
use super::*;
use std::{os::unix::fs::MetadataExt, time::Instant};

impl Terminal {
    pub(crate) fn approve_born_dispatch_until_v1(
        &self,
        digest: &str,
        detail: &str,
        deadline: Instant,
        check: impl Fn() -> Result<()>,
    ) -> Result<PublicationApproval> {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || detail.len() > 65_536
        {
            return Err(Error::Invalid);
        }
        // Another terminal job must not trap all held wallet DB guards.
        let original = self.0.try_lock().map_err(|_| Error::Permission)?;
        current(&original, deadline, &check)?;
        // A new open file description avoids changing the flags of any shared
        // terminal handle. This is the same actual controlling TTY, not stdin.
        let mut io = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open("/dev/tty")
            .map_err(|_| Error::Terminal)?;
        let a = original.metadata()?;
        let b = io.metadata()?;
        if !b.file_type().is_char_device()
            || (a.dev(), a.ino(), a.rdev()) != (b.dev(), b.ino(), b.rdev())
        {
            return Err(Error::Terminal);
        }
        let challenge = format!("APPROVE {}", hex::encode(random::<8>()?));
        let mut rendered = sanitize(detail);
        rendered.push_str(&format!(
            "\nType {challenge} to approve this exact operation, or anything else to reject: "
        ));
        write_until(&mut io, rendered.as_bytes(), deadline, &check)?;
        let mut response = Zeroizing::new(Vec::new());
        loop {
            current(&io, deadline, &check)?;
            let mut byte = [0];
            match io.read(&mut byte) {
                Ok(0) => return Err(Error::Terminal),
                Ok(_) if byte[0] == b'\n' => break,
                Ok(_) if response.len() < 8192 => response.push(byte[0]),
                Ok(_) => return Err(Error::Invalid),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    ready(&io, libc::POLLIN, deadline, &check)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(Error::Terminal),
            }
        }
        current(&io, deadline, &check)?;
        if std::str::from_utf8(&response)
            .map_err(|_| Error::Invalid)?
            .trim_end_matches('\r')
            != challenge
        {
            return Err(Error::Permission);
        }
        current(&original, deadline, &check)?;
        Ok(PublicationApproval {
            terminal: self.clone(),
            foreground_file: original.try_clone()?,
            manifest_digest: digest.into(),
            deadline,
        })
    }
}
fn current(file: &File, deadline: Instant, check: &impl Fn() -> Result<()>) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(Error::Permission);
    }
    foreground(file)?;
    check()?;
    if Instant::now() >= deadline {
        return Err(Error::Permission);
    }
    foreground(file)
}
fn ready(
    file: &File,
    events: i16,
    deadline: Instant,
    check: &impl Fn() -> Result<()>,
) -> Result<()> {
    current(file, deadline, check)?;
    let wait = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(50) as i32;
    if wait == 0 {
        return Err(Error::Permission);
    }
    let mut descriptor = libc::pollfd {
        fd: file.as_raw_fd(),
        events,
        revents: 0,
    };
    // SAFETY: the owned live TTY descriptor and one valid pollfd remain borrowed.
    let result = unsafe { libc::poll(&mut descriptor, 1, wait) };
    if result < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
        || descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
    {
        return Err(Error::Terminal);
    }
    current(file, deadline, check)
}
fn write_until(
    file: &mut File,
    mut bytes: &[u8],
    deadline: Instant,
    check: &impl Fn() -> Result<()>,
) -> Result<()> {
    while !bytes.is_empty() {
        current(file, deadline, check)?;
        match file.write(bytes) {
            Ok(0) => return Err(Error::Terminal),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                ready(file, libc::POLLOUT, deadline, check)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::Terminal),
        }
    }
    current(file, deadline, check)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn busy_or_disconnected_terminal_denies_without_waiting_or_effect() {
        let terminal = Terminal::disconnected_for_test();
        let digest = "a".repeat(64);
        let held = terminal.0.lock().unwrap();
        assert!(
            terminal
                .approve_born_dispatch_until_v1(
                    &digest,
                    "synthetic no authority",
                    Instant::now() + std::time::Duration::from_secs(1),
                    || panic!("busy terminal cannot disclose")
                )
                .is_err()
        );
        drop(held);
        assert!(
            terminal
                .approve_born_dispatch_until_v1(
                    &digest,
                    "synthetic no authority",
                    Instant::now() + std::time::Duration::from_secs(1),
                    || panic!("disconnected terminal cannot disclose")
                )
                .is_err()
        );
    }
}
