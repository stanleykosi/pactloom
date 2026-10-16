//! Signer-controlled Linux terminal surface. Approval and secret entry never read
//! stdin supplied by the integrating application. No public mockable UI trait.
//! A controlling TTY is NOT proof of user origin: an app can own a PTY/session.
//! This surface remains unqualified for live release and real credential setup.
use crate::{
    account::{BackupVerifiedAccount, PendingAccount, ProvisioningConsent},
    review::{validate_label, HumanApprovedReview, PreparedReview},
    Error, Result,
};
use std::{
    fs::{File, OpenOptions},
    io::{IsTerminal, Read, Write},
};
use zeroize::Zeroizing;

pub struct TrustedTerminal {
    terminal: File,
}
impl TrustedTerminal {
    pub fn open() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::{
                fs::{FileTypeExt, OpenOptionsExt},
                io::AsRawFd,
            };
            let terminal = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/dev/tty")?;
            if !terminal.metadata()?.file_type().is_char_device() || !terminal.is_terminal() {
                return Err(Error::Unavailable);
            }
            // Require the signer's process group to own the foreground terminal.
            // SAFETY: tcgetpgrp/getpgrp operate on a valid open terminal fd.
            if unsafe { libc::tcgetpgrp(terminal.as_raw_fd()) != libc::getpgrp() } {
                return Err(Error::Unavailable);
            }
            Ok(Self { terminal })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::Unavailable)
        }
    }
    fn check_foreground(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: the terminal file remains open and these calls only inspect groups.
            if !self.terminal.is_terminal()
                || unsafe { libc::tcgetpgrp(self.terminal.as_raw_fd()) != libc::getpgrp() }
            {
                return Err(Error::Unavailable);
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::Unavailable)
        }
    }
    pub fn user_origin_authenticated(&self) -> bool {
        false
    }
    fn write(&mut self, text: &str) -> Result<()> {
        self.check_foreground()?;
        self.terminal.write_all(text.as_bytes())?;
        self.terminal.flush()?;
        Ok(())
    }
    fn read_line(&mut self) -> Result<Zeroizing<String>> {
        let mut bytes = Zeroizing::new(Vec::new());
        loop {
            self.check_foreground()?;
            let mut byte = [0];
            if self.terminal.read(&mut byte)? == 0 {
                return Err(Error::ReviewMismatch);
            }
            if byte[0] == b'\n' {
                break;
            }
            if bytes.len() >= 1024 {
                return Err(Error::InvalidData);
            }
            bytes.push(byte[0]);
        }
        let value = std::str::from_utf8(&bytes).map_err(|_| Error::InvalidData)?;
        Ok(Zeroizing::new(value.trim_end_matches('\r').to_string()))
    }
    pub fn accept_manifest(
        &mut self,
        input: wholepact_core::ProposalInput,
    ) -> Result<crate::manifest::AcceptedManifest> {
        let proposal =
            wholepact_core::Proposal::validate(input).map_err(|_| Error::Verification)?;
        let text =
            serde_json::to_string_pretty(proposal.input()).map_err(|_| Error::InvalidData)?;
        self.write("Review the complete application agreement below. This step checks syntax/accounting only. Recipient provenance and other account identities remain unverified unless independently checked. Acceptance does not sign.\n")?;
        let mut safe = String::new();
        for ch in text.chars() {
            if ch == '\n' || ch.is_ascii_graphic() || ch == ' ' {
                safe.push(ch)
            } else {
                safe.extend(ch.escape_default())
            }
        }
        self.write(&safe)?;
        let expected = format!("ACCEPT {}", proposal.manifest_digest());
        self.write(&format!(
            "\nType exactly '{expected}' to accept these application terms: "
        ))?;
        if self.read_line()?.as_str() != expected {
            return Err(Error::ReviewMismatch);
        }
        Ok(crate::manifest::AcceptedManifest { proposal })
    }
    pub fn approve_review(&mut self, review: PreparedReview) -> Result<HumanApprovedReview> {
        self.write(review.display())?;
        let expected = review.challenge();
        self.write(&format!(
            "\nType exactly '{expected}' to accept this review, or anything else to reject: "
        ))?;
        let response = self.read_line()?;
        review.approve(&response)
    }
    pub fn approve_new_account(
        &mut self,
        privacy_domain: &str,
        account_index: u32,
    ) -> Result<ProvisioningConsent> {
        if !self.user_origin_authenticated() {
            return Err(Error::Unavailable);
        }
        validate_label(privacy_domain)?;
        if account_index >= 1 << 31 {
            return Err(Error::InvalidData);
        }
        self.write(&format!("Create a NEW dedicated testnet account for privacy domain {privacy_domain}.\nRecovery: 24 English BIP39 words, empty BIP39 passphrase, legacy ZIP32 m/32'/1'/{account_index}'.\nDo not reuse an everyday wallet. The full phrase must be backed up and re-entered. Password loss without recovery words loses wallet access. Seed recovery alone cannot restore off-chain authorizations. Live signing remains unavailable.\nType CREATE DEDICATED TESTNET ACCOUNT to proceed: "))?;
        if self.read_line()?.as_str() != "CREATE DEDICATED TESTNET ACCOUNT" {
            return Err(Error::ReviewMismatch);
        }
        Ok(ProvisioningConsent {
            privacy_domain: privacy_domain.into(),
            account_index,
        })
    }
    pub fn verify_recovery_backup(
        &mut self,
        pending: PendingAccount,
    ) -> Result<BackupVerifiedAccount> {
        if !self.user_origin_authenticated() {
            return Err(Error::Unavailable);
        }
        let words = pending.recovery_words()?;
        self.write("Write down these new account recovery words privately. Anyone with them can control that account. They will not be sent to an app or logged.\n")?;
        self.write(&words)?;
        self.write("\nPress Enter after recording the words.\n")?;
        let _ = self.read_line()?;
        self.write("Re-enter all 24 words to verify the backup. Input is hidden.\n")?;
        self.check_foreground()?;
        let entered = Zeroizing::new(rpassword::prompt_password("Recovery words: ")?);
        self.check_foreground()?;
        pending.verify_backup(&entered)
    }
    pub fn unlock_password(&mut self) -> Result<Zeroizing<String>> {
        if !self.user_origin_authenticated() {
            return Err(Error::Unavailable);
        }
        self.write("Unlock the dedicated signer vault. Password input stays on this controlling terminal.\n")?;
        self.check_foreground()?;
        let password = Zeroizing::new(rpassword::prompt_password("Vault password: ")?);
        self.check_foreground()?;
        if password.len() < 12 || password.len() > 1024 {
            return Err(Error::Authentication);
        }
        Ok(password)
    }
}
