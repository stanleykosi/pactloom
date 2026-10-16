//! Source foundation: exact pending-request crash recovery. This preserves already
//! encrypted request bytes; it cannot issue, renew, sign, enroll or activate.
//! Only a real fresh native decision can promote the one authenticated stage.
use super::request::{MAX_REQUEST, REQUEST_FILE, RetainedPendingOwnerRequest};
use super::*;
use wholepact_authority::pending_birth::PendingBirthRequest;

/// Structural inventory only. A recognized filename is never authentication.
pub(super) struct PendingRequestInventory {
    staged_name: Option<String>,
    retained_request: bool,
}

fn is_stage_name(name: &str) -> bool {
    name.len() == 36 && name.starts_with("tmp-") && name[4..].bytes().all(is_hex)
}

/// Called before password opening, and again before any publication. There is
/// no cleanup path: unknown, multiple, non-private or conflicting entries deny.
pub(super) fn scan_pending_inventory(
    directory: &PrivateDirectory,
) -> Result<PendingRequestInventory> {
    use std::os::unix::fs::MetadataExt;
    let mut names = std::collections::BTreeSet::new();
    let mut staged_name = None;
    let mut staged_size = 0;
    for entry in std::fs::read_dir(directory.root())? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Error::InvalidData)?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(Error::InvalidData);
        }
        match name.as_str() {
            "account.wp" | "signer.lock" | REQUEST_FILE => {}
            _ if is_stage_name(&name) && staged_name.is_none() => {
                if metadata.len() > 512 * 1024 {
                    return Err(Error::InvalidData);
                }
                staged_size = metadata.len();
                staged_name = Some(name.clone());
            }
            _ => return Err(Error::InvalidData),
        }
        names.insert(name);
    }
    if !names.contains("account.wp")
        || !names.contains("signer.lock")
        || !(2..=4).contains(&names.len())
        || (!names.contains(REQUEST_FILE) && staged_size > MAX_REQUEST as u64)
    {
        return Err(Error::InvalidData);
    }
    Ok(PendingRequestInventory {
        staged_name,
        retained_request: names.contains(REQUEST_FILE),
    })
}

/// Audit read tied to an authenticated pending owner. No clone, deserializer,
/// approval flag or public constructor. It holds exact ciphertext, not new times.
pub(crate) struct StagedPendingOwnerRequest<'a> {
    pending: &'a PendingBirthVault,
    name: String,
    encrypted: Vec<u8>,
    request: PendingBirthRequest,
}
impl StagedPendingOwnerRequest<'_> {
    pub(crate) fn request(&self) -> &PendingBirthRequest {
        &self.request
    }
    pub(crate) fn recheck_original(&self) -> Result<()> {
        let current = self
            .pending
            .staged_owner_request()?
            .ok_or(Error::RecoveryRequired)?;
        if self.name != current.name
            || self.encrypted != current.encrypted
            || self.request != current.request
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}

/// Pure authentication/anchor validation shared with source-only data tests.
/// A decoded request is still only data, never native authority.
fn decode_stage(
    key: &[u8; 32],
    domain: &[u8],
    anchor: &BirthAnchor,
    encrypted: &[u8],
) -> Result<PendingBirthRequest> {
    if encrypted.len() > MAX_REQUEST {
        return Err(Error::InvalidData);
    }
    let plain = vault::decrypt(key, domain, encrypted)?;
    let request: PendingBirthRequest =
        serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
    anchor.require_exact_pending_request(&request)?;
    Ok(request)
}

impl PendingBirthVault {
    /// A stage, including an expired stage, blocks all new request preparation.
    /// Authentication failures are not an invitation to discard and start over.
    pub(super) fn require_no_staged_owner_request(&self) -> Result<()> {
        if scan_pending_inventory(&self._directory)?
            .staged_name
            .is_some()
        {
            return Err(Error::RecoveryRequired);
        }
        Ok(())
    }
    pub(super) fn validate_request_recovery_inventory(&self) -> Result<()> {
        let inventory = scan_pending_inventory(&self._directory)?;
        if inventory.retained_request && inventory.staged_name.is_some() {
            // A final request plus a stage is never another owner request. Only
            // the separate authenticated active-envelope decoder may accept it.
            super::active::authenticate_staged_envelope(self)?.ok_or(Error::RecoveryRequired)?;
            self.read_owner_request()?;
        } else if self.staged_owner_request()?.is_none() {
            self.read_owner_request()?;
        }
        Ok(())
    }
    /// The password-open path must call this (or validation above) after opening
    /// the real pending envelope. The recognized tmp name alone is insufficient.
    pub(crate) fn staged_owner_request(&self) -> Result<Option<StagedPendingOwnerRequest<'_>>> {
        let inventory = scan_pending_inventory(&self._directory)?;
        if inventory.retained_request && inventory.staged_name.is_some() {
            super::active::authenticate_staged_envelope(self)?.ok_or(Error::RecoveryRequired)?;
            return Ok(None);
        }
        let Some(name) = inventory.staged_name else {
            return Ok(None);
        };
        let encrypted = self._directory.read(&name, MAX_REQUEST)?;
        let request = decode_stage(
            &self.encryption_key,
            &self.request_domain()?,
            &self.anchor,
            &encrypted,
        )?;
        Ok(Some(StagedPendingOwnerRequest {
            pending: self,
            name,
            encrypted,
            request,
        }))
    }
    /// Data-only classification after authentication; not publication authority.
    pub(crate) fn has_staged_born_acknowledgement(&self) -> Result<bool> {
        let inventory = scan_pending_inventory(&self._directory)?;
        if inventory.retained_request && inventory.staged_name.is_some() {
            return Ok(super::active::authenticate_staged_envelope(self)?.is_some());
        }
        Ok(false)
    }
    pub(crate) fn prepare_staged_owner_request_recovery(
        self: &Arc<Self>,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PreparedPendingOwnerRequestRecovery> {
        owner.check_current()?;
        self.require_original_request_target()?;
        let staged = self
            .staged_owner_request()?
            .ok_or(Error::RecoveryRequired)?;
        let source = owner.native().binding();
        let review_digest = canonical(
            "wholepact:native-pending-owner-request-recovery:v1",
            &(
                staged.request.digest().map_err(|_| Error::InvalidData)?,
                staged.name.as_str(),
                hex::encode(Sha256::digest(&staged.encrypted)),
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )?;
        Ok(PreparedPendingOwnerRequestRecovery {
            pending: Arc::clone(self),
            name: staged.name,
            encrypted: staged.encrypted,
            request: staged.request,
            source,
            review_digest,
            created: Instant::now(),
        })
    }
}

pub(crate) struct PreparedPendingOwnerRequestRecovery {
    pending: Arc<PendingBirthVault>,
    name: String,
    encrypted: Vec<u8>,
    request: PendingBirthRequest,
    source: NativeAuthorityBinding,
    review_digest: String,
    created: Instant,
}
impl PreparedPendingOwnerRequestRecovery {
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.review_digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Review<'r> {
            purpose: &'static str,
            pending_directory: &'r str,
            staging_file: &'r str,
            ciphertext_digest: String,
            request: &'r PendingBirthRequest,
        }
        serde_json::to_string_pretty(&Review {
            purpose: "Preserve this existing encrypted request exactly as audit. No timestamps are changed. This does not sign, enroll or activate. A first witness commit still requires the original deadline and separate authority.",
            pending_directory: self.pending._directory.root().to_str().ok_or(Error::InvalidData)?,
            staging_file: &self.name,
            ciphertext_digest: hex::encode(Sha256::digest(&self.encrypted)),
            request: &self.request,
        }).map_err(|_| Error::InvalidData)
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        owner.check_current()?;
        self.source.check_current()?;
        if self.created.elapsed() >= REVIEW_LIFETIME || self.source != owner.native().binding() {
            return Err(Error::ReviewMismatch);
        }
        self.pending.require_original_request_target()?;
        // Deliberately no current initial-commit-time check: preserving an expired
        // request is audit only. Its original first-commit deadline is unchanged.
        let current = self
            .pending
            .staged_owner_request()?
            .ok_or(Error::RecoveryRequired)?;
        if current.name != self.name
            || current.encrypted != self.encrypted
            || current.request != self.request
        {
            return Err(Error::ReviewMismatch);
        }
        current.recheck_original()
    }
    /// Same supported-writer contract as PrivateDirectory: its held directory
    /// lock and this owner's mutex exclude supported conflicting writes. This is
    /// not hostile-same-user protection. No unlink, overwrite or reprepare route.
    pub(crate) fn preserve_exact(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<RetainedPendingOwnerRequest> {
        self.check(owner)?;
        if decision.binding() != &self.source || decision.reviewed_digest() != self.review_digest {
            return Err(Error::ReviewMismatch);
        }
        let _request_publication = self
            .pending
            .request_publication
            .lock()
            .map_err(|_| Error::Locked)?;
        let _publication = self.source.publication_lease()?;
        self.check(owner)?;
        let pending = &self.pending;
        // The previous writer may have died before syncing the temporary name
        // into the directory. Establish a durable exact source before rename,
        // so another interrupted recovery cannot lose both source and final.
        pending._directory.sync_all_files()?;
        self.check(owner)?;
        // Exact full inventory and ciphertext were rechecked under both leases.
        // std::fs::rename is atomic; the final name was verified absent. No
        // supported writer can create/replace it while this mutex/lock is held.
        if pending._directory.exists(REQUEST_FILE)? {
            return Err(Error::ReviewMismatch);
        }
        std::fs::rename(
            pending._directory.root().join(&self.name),
            pending._directory.root().join(REQUEST_FILE),
        )?;
        pending._directory.sync_all_files()?;
        // If rename or fsync was interrupted, reopen sees either the original
        // stage or final record. A failure returns no authority or success handle.
        pending.require_no_staged_owner_request()?;
        if pending._directory.read(REQUEST_FILE, MAX_REQUEST)? != self.encrypted {
            return Err(Error::ReviewMismatch);
        }
        let retained = pending
            .retained_owner_request()?
            .ok_or(Error::RecoveryRequired)?;
        if retained.request() != &self.request {
            return Err(Error::ReviewMismatch);
        }
        Ok(retained)
    }
}

#[cfg(test)]
mod tests;
