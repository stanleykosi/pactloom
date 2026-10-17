//! Explicit foreground Linux TTY. Never stdin/env/argv/browser secret entry.
//! This is local non-signing consent, not attestation against same-user PTY spoofing.
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub(crate) mod born_checkpoint_retention_v1;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub(crate) mod born_offline_proof_v1;
#[cfg(all(feature = "manual-admission", target_os = "linux"))]
pub(crate) mod born_dispatch_v1;
#[cfg(feature = "financial-runtime")]
pub(crate) mod historical;
use crate::{Error, Result, random};
#[cfg(target_os = "linux")]
use std::os::unix::{
    fs::{FileTypeExt, OpenOptionsExt},
    io::AsRawFd,
};
use std::{
    fs::{File, OpenOptions},
    io::{IsTerminal, Read, Write},
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;
#[derive(Clone)]
pub(crate) struct Terminal(Arc<Mutex<File>>);

/// One exact foreground-native publication decision. It is neither serializable
/// nor renewable. The terminal lock serializes the final local effect with other
/// local terminal interactions; hostile OS/PTY manipulation is outside this
/// boundary. Losing foreground or the terminal before admission denies the write.
#[cfg(feature = "financial-runtime")]
pub(crate) struct PublicationApproval {
    terminal: Terminal,
    foreground_file: File,
    manifest_digest: String,
    deadline: std::time::Instant,
}
#[cfg(feature = "financial-runtime")]
impl PublicationApproval {
    /// Restriction-only monotonic bound, never an approval constructor.
    pub(crate) fn deadline(&self) -> std::time::Instant {
        self.deadline
    }

    pub(crate) fn check(&self) -> Result<()> {
        // A private duplicate of the exact approved TTY permits restriction
        // checks inside commit without recursively taking its effect mutex.
        if std::time::Instant::now() >= self.deadline {
            return Err(Error::Permission);
        }
        foreground(&self.foreground_file)
    }
    pub(crate) fn commit<P, T>(
        self,
        digest: &str,
        prepare: impl FnOnce() -> Result<P>,
        effect: impl FnOnce(P) -> Result<T>,
    ) -> Result<T> {
        let file = self.terminal.0.lock().map_err(|_| Error::Terminal)?;
        if digest != self.manifest_digest || std::time::Instant::now() >= self.deadline {
            return Err(Error::Permission);
        }
        foreground(&file)?;
        // Complete validation can allocate writable journal handles and touch
        // their sidecars. Admit that work only while this same effect is held.
        let prepared = prepare()?;
        // Preparation can be expensive. Retain the independent deadline and
        // foreground check immediately before admitting the durable marker.
        if std::time::Instant::now() >= self.deadline {
            return Err(Error::Permission);
        }
        foreground(&file)?;
        // The bounded approval admits this exact write. Expiry after admission
        // cannot undo a partially written/fsynced marker; finish its durable write.
        let result = effect(prepared);
        drop(file);
        result
    }

    #[cfg(test)]
    pub(crate) fn denied_for_test(manifest_digest: &str, expired: bool) -> Self {
        // Negative fixture only. A regular file can never satisfy foreground()
        // and therefore cannot authorize any preparation or publication effect.
        let terminal = Terminal::disconnected_for_test();
        let foreground_file = terminal.0.lock().unwrap().try_clone().unwrap();
        Self {
            terminal,
            foreground_file,
            manifest_digest: manifest_digest.into(),
            deadline: if expired {
                std::time::Instant::now()
            } else {
                std::time::Instant::now() + std::time::Duration::from_secs(300)
            },
        }
    }
}
impl Terminal {
    #[cfg(test)]
    pub(crate) fn disconnected_for_test() -> Self {
        Self(Arc::new(Mutex::new(
            tempfile::tempfile().expect("synthetic terminal file"),
        )))
    }
    #[cfg(feature = "financial-runtime")]
    pub(crate) fn approve_publication(
        &self,
        manifest_digest: &str,
        detail: &str,
    ) -> Result<PublicationApproval> {
        if manifest_digest.len() != 64
            || !manifest_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid);
        }
        self.confirm(detail)?;
        let file = self.0.lock().map_err(|_| Error::Terminal)?;
        foreground(&file)?;
        Ok(PublicationApproval {
            terminal: self.clone(),
            foreground_file: file.try_clone()?,
            manifest_digest: manifest_digest.into(),
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(300),
        })
    }
    pub(crate) fn open() -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(Error::Platform);
        }
        #[cfg(target_os = "linux")]
        {
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/dev/tty")
                .map_err(|_| Error::Terminal)?;
            if !f.metadata()?.file_type().is_char_device() {
                return Err(Error::Terminal);
            }
            foreground(&f)?;
            Ok(Self(Arc::new(Mutex::new(f))))
        }
    }
    pub(crate) fn message(&self, text: &str) -> Result<()> {
        let mut f = self.0.lock().map_err(|_| Error::Terminal)?;
        foreground(&f)?;
        f.write_all(sanitize(text).as_bytes())?;
        f.flush()?;
        Ok(())
    }
    pub(crate) fn ask(&self, prompt: &str) -> Result<Zeroizing<String>> {
        let mut f = self.0.lock().map_err(|_| Error::Terminal)?;
        foreground(&f)?;
        f.write_all(sanitize(prompt).as_bytes())?;
        f.flush()?;
        line(&mut f)
    }
    pub(crate) fn secret(&self, prompt: &str) -> Result<Zeroizing<String>> {
        let mut f = self.0.lock().map_err(|_| Error::Terminal)?;
        foreground(&f)?;
        f.write_all(sanitize(prompt).as_bytes())?;
        f.flush()?;
        // rpassword reads the controlling TTY directly, not piped stdin.
        let secret = Zeroizing::new(rpassword::read_password().map_err(|_| Error::Terminal)?);
        foreground(&f)?;
        if secret.len() < 12 || secret.len() > 1024 {
            return Err(Error::Authentication);
        }
        Ok(secret)
    }
    pub(crate) fn confirm(&self, detail: &str) -> Result<()> {
        self.confirm_checked(detail, || Ok(()))
    }
    /// Check an existing private-review scope under the terminal mutex before
    /// displaying its exact metadata. The guard must not re-lock this Terminal.
    pub(crate) fn confirm_checked(
        &self,
        detail: &str,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let rendered = sanitize(detail);
        let challenge = format!("APPROVE {}", hex::encode(random::<8>()?));
        let prompt = format!(
            "\nType {challenge} to approve this exact operation, or anything else to reject: "
        );
        let mut f = self.0.lock().map_err(|_| Error::Terminal)?;
        foreground(&f)?;
        check()?;
        // Rendering and mutex waiting precede this exact disclosure admission.
        // Bytes already accepted by an OS write cannot be recalled.
        f.write_all(rendered.as_bytes())?;
        f.write_all(prompt.as_bytes())?;
        f.flush()?;
        if line(&mut f)?.as_str() != challenge {
            return Err(Error::Permission);
        }
        Ok(())
    }
    pub(crate) fn json<T: serde::Serialize>(&self, value: &T) -> Result<()> {
        let mut text = Zeroizing::new(serde_json::to_string_pretty(value)?);
        text.push('\n');
        self.message(&text)
    }
}
/// Pure projection for the finite synthetic PTY driver. It must expect exactly
/// the bytes the maintained terminal renderer writes, never a raw-text fallback.
/// No runtime binary exposes this helper, and no response is transformed.
#[cfg(test)]
pub(crate) fn render_synthetic_expected_prompt(s: &str) -> Zeroizing<String> {
    sanitize(s)
}

fn sanitize(s: &str) -> Zeroizing<String> {
    Zeroizing::new(
        s.chars()
            .flat_map(|c| {
                if c == '\n' || c == ' ' || c.is_ascii_graphic() {
                    vec![c]
                } else {
                    c.escape_default().collect()
                }
            })
            .collect(),
    )
}
fn foreground(f: &File) -> Result<()> {
    #[cfg(target_os = "linux")]
    // SAFETY: these calls inspect a live owned TTY descriptor/process group.
    if f.is_terminal() && unsafe { libc::tcgetpgrp(f.as_raw_fd()) == libc::getpgrp() } {
        return Ok(());
    }
    let _ = f;
    Err(Error::Terminal)
}
fn line(f: &mut File) -> Result<Zeroizing<String>> {
    let mut b = Zeroizing::new(Vec::new());
    loop {
        foreground(f)?;
        let mut c = [0];
        if f.read(&mut c)? == 0 {
            return Err(Error::Terminal);
        }
        if c[0] == b'\n' {
            break;
        }
        if b.len() >= 8192 {
            return Err(Error::Invalid);
        }
        b.push(c[0]);
    }
    Ok(Zeroizing::new(
        std::str::from_utf8(&b)
            .map_err(|_| Error::Invalid)?
            .trim_end_matches('\r')
            .to_owned(),
    ))
}

#[cfg(all(test, feature = "financial-runtime"))]
mod publication_tests {
    use super::*;
    #[test]
    fn nested_restriction_check_does_not_relock_held_terminal() {
        for expired in [false, true] {
            let approval = PublicationApproval::denied_for_test(&"a".repeat(64), expired);
            let _held = approval.terminal.0.lock().unwrap();
            assert!(approval.check().is_err());
        }
    }
    #[test]
    fn disconnected_or_expired_native_publication_never_runs_effect() {
        let terminal = Terminal(Arc::new(Mutex::new(tempfile::tempfile().unwrap())));
        for (expected, supplied, deadline) in [
            (
                "aa".repeat(32),
                "aa".repeat(32),
                std::time::Instant::now() + std::time::Duration::from_secs(30),
            ),
            (
                "aa".repeat(32),
                "bb".repeat(32),
                std::time::Instant::now() + std::time::Duration::from_secs(30),
            ),
            ("aa".repeat(32), "aa".repeat(32), std::time::Instant::now()),
        ] {
            // Regular-file substitute models loss of the controlling terminal;
            // it is never used as a successful synthetic native approval.
            let approval = PublicationApproval {
                terminal: terminal.clone(),
                foreground_file: terminal.0.lock().unwrap().try_clone().unwrap(),
                manifest_digest: expected,
                deadline,
            };
            let prepared = std::cell::Cell::new(false);
            let invoked = std::cell::Cell::new(false);
            assert!(
                approval
                    .commit(
                        &supplied,
                        || {
                            prepared.set(true);
                            Ok(())
                        },
                        |()| {
                            invoked.set(true);
                            Ok(())
                        },
                    )
                    .is_err()
            );
            assert!(!prepared.get());
            assert!(!invoked.get());
        }
    }
}
