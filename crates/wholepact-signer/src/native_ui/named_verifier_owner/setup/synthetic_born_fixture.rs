//! Opt-in, never-funded controller fixture. Every creation/transport operation
//! consumes the existing native exact review. No raw decision, authority,
//! verifier owner or private key leaves this finite wrapper.
use super::*;
use std::sync::Arc;

const PASSWORD: &str = "synthetic-only-never-funded-verifier-profile";
const EPOCH: u64 = 1;

/// Owns only the actual separately created temporary verifier installation.
/// This is synthetic event delivery, not proof of attended-human acceptance.
pub struct EphemeralNamedVerifierV1 {
    workspace: SetupWorkspace,
    completed_row: Option<String>,
    _temporary: Arc<tempfile::TempDir>,
}
impl Drop for EphemeralNamedVerifierV1 {
    fn drop(&mut self) {
        // Cancel and fully drain any actual assertion worker before dropping
        // native/key owners and the never-funded fixture installation.
        if let Some(assertion) = &mut self.workspace.assertion { assertion.drain_synthetic_original(); }
        self.workspace.clear();
    }
}
impl EphemeralNamedVerifierV1 {
    pub fn create() -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let temporary = Arc::new(
            tempfile::Builder::new()
                .prefix("wholepact-synthetic-born-verifier-")
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir()?,
        );
        let mut this = Self {
            workspace: SetupWorkspace::default(),
            completed_row: None,
            _temporary: temporary.clone(),
        };
        this.workspace.begin();
        this.workspace.path = temporary
            .path()
            .join("actual-verifier-profile")
            .to_str()
            .ok_or(Error::InvalidData)?
            .into();
        this.workspace.password = Zeroizing::new(PASSWORD.into());
        // The SAME production entry creates its own native source. The fixture
        // cannot supply token fields, a source, an approval or a signing key.
        this.workspace.stage_create(EPOCH)?;
        this.consume_setup_review(false)?;
        this.workspace.stage_export_step(0, EPOCH)?;
        this.consume_setup_review(true)?;
        this.public_keys()?;
        Ok(this)
    }

    fn consume_setup_review(&mut self, transport: bool) -> Result<()> {
        if self.workspace.assertion.is_some() || !self.workspace.is_active() {
            return Err(Error::ReviewMismatch);
        }
        let pending = self.workspace.pending.as_mut().ok_or(Error::Locked)?;
        if !matches!(
            (&pending.step, transport),
            (Step::Create(_), false) | (Step::Transport(_), true)
        ) || pending.exact.confirming()
            || pending.exact.display().is_empty()
        {
            return Err(Error::ReviewMismatch);
        }
        self.workspace.frame = self.workspace.frame.saturating_add(1);
        if self.workspace.frame <= pending.shown
            || pending
                .exact
                .continue_from_native_click(false, EPOCH)
                .is_ok()
            || pending
                .exact
                .continue_from_native_click(true, EPOCH + 1)
                .is_ok()
        {
            return Err(Error::ReviewMismatch);
        }
        pending.exact.continue_from_native_click(true, EPOCH)?;
        pending.continued = Some(self.workspace.frame);
        self.workspace.frame = self.workspace.frame.saturating_add(1);
        if !pending
            .continued
            .is_some_and(|frame| self.workspace.frame > frame)
        {
            return Err(Error::ReviewMismatch);
        }
        self.workspace.phrase =
            Zeroizing::new(format!("AUTHORIZE {}", &pending.exact.digest()[..12]));
        // Existing production dispatcher consumes the actual staged review and
        // performs the maintained key/profile/outbox operation.
        self.workspace.consume(true, EPOCH)?;
        if self.workspace.pending.is_some() || self.workspace.assertion.is_some() {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }

    /// Actual immutable public identities only. They confer no assertion or
    /// disclosure authority and are never a projection of a caller-supplied key.
    pub fn public_keys(&self) -> Result<([u8; 32], [u8; 32])> {
        let owner = self.workspace.owner.as_ref().ok_or(Error::Locked)?;
        owner.check_current()?;
        let identity = owner
            .journal
            .export_identity
            .as_ref()
            .ok_or(Error::Locked)?;
        identity.validate()?;
        if identity.state != super::super::export_identity::SetupState::Ready
            || self.workspace.assertion.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        let transport =
            wholepact_transport::TransportSecret::from_bytes(identity.secrets.transport)
                .and_then(|secret| secret.public_key())
                .map_err(|_| Error::Verification)?;
        owner.check_current()?;
        Ok((owner.public_key(), *transport.as_bytes()))
    }
}

#[path = "synthetic_born_assertion.rs"]
mod assertion_fixture;
