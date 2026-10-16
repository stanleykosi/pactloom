//! Source foundation: signer account::birth child. Exact pending request is durably
//! retained before it can be signed/exported. This supplies no signing capability.
use super::*;
use wholepact_authority::pending_birth::PendingBirthRequest;

pub(super) const REQUEST_FILE: &str = "birth-owner-request.wp";
pub(super) const MAX_REQUEST: usize = 128 * 1024;
const REQUEST_LIFETIME_MS: u64 = 120_000;

/// Prepared data tied to the actual held pending envelope and native owner.
/// No public constructor, deserializer, clone or test approval factory exists.
pub(crate) struct PreparedPendingOwnerRequest {
    pending: Arc<PendingBirthVault>,
    source: NativeAuthorityBinding,
    request: PendingBirthRequest,
    review_digest: String,
    created: Instant,
}
/// Retained request audit only. The held Arc keeps the authenticated vault and
/// its actual directory lock alive across the bounded native worker handoff.
/// No method obtains a spending/owner key or produces a witness creation token.
pub(crate) struct RetainedPendingOwnerRequest {
    pending: Arc<PendingBirthVault>,
    request: PendingBirthRequest,
}
impl RetainedPendingOwnerRequest {
    pub(crate) fn request(&self) -> &PendingBirthRequest {
        &self.request
    }
    pub(crate) fn recheck_original(&self) -> Result<()> {
        self.pending.require_no_staged_owner_request()?;
        self.recheck_for_acknowledgement()
    }
    /// Audit/history only: a finalized request may coexist solely with an
    /// authenticated exact born-envelope stage. This never permits signing.
    pub(crate) fn recheck_for_acknowledgement(&self) -> Result<()> {
        self.pending.validate_request_recovery_inventory()?;
        let stored = self
            .pending
            .read_owner_request()?
            .ok_or(Error::RecoveryRequired)?;
        if stored != self.request {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
}
impl PendingBirthVault {
    pub(super) fn require_original_request_target(&self) -> Result<()> {
        self.check_pending_envelope()?;
        if self._directory.root().to_str() != Some(self.anchor.intent.original_target.as_str()) {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }
    pub(super) fn request_domain(&self) -> Result<Vec<u8>> {
        let mut domain = b"wholepact:pending-birth-owner-request-envelope:v1\0".to_vec();
        domain.extend_from_slice(self.anchor.birth_digest().as_bytes());
        Ok(domain)
    }
    pub(super) fn read_owner_request(&self) -> Result<Option<PendingBirthRequest>> {
        self.check_pending_envelope()?;
        if !self._directory.exists(REQUEST_FILE)? {
            return Ok(None);
        }
        let bytes = self._directory.read(REQUEST_FILE, MAX_REQUEST)?;
        let plain = vault::decrypt(&self.encryption_key, &self.request_domain()?, &bytes)?;
        let request: PendingBirthRequest =
            serde_json::from_slice(&plain).map_err(|_| Error::InvalidData)?;
        self.anchor.require_exact_pending_request(&request)?;
        Ok(Some(request))
    }
    /// Existing retained request can only be read exactly. This is audit evidence
    /// even after expiry; later signature/key use needs fresh native consent and
    /// the original initial-commit deadline. This does not change that deadline.
    pub(crate) fn retained_owner_request(
        self: &Arc<Self>,
    ) -> Result<Option<RetainedPendingOwnerRequest>> {
        Ok(self
            .read_owner_request()?
            .map(|request| RetainedPendingOwnerRequest {
                pending: Arc::clone(self),
                request,
            }))
    }
    pub(crate) fn prepare_owner_request(
        self: &Arc<Self>,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<PreparedPendingOwnerRequest> {
        owner.check_current()?;
        self.require_original_request_target()?;
        self.require_no_staged_owner_request()?;
        // Restart must show/review the original request, never overwrite it.
        if self.read_owner_request()?.is_some() {
            return Err(Error::ReviewMismatch);
        }
        let mut policy: AccountPolicy =
            serde_json::from_str(&self.anchor.original_policy_terms().audit_json()?)
                .map_err(|_| Error::InvalidData)?;
        policy.account_use_genesis = Some(self.anchor.expected_account_use_genesis()?);
        let (_, disclosure) = self.anchor.audit_policy_match(&policy)?;
        let issued_at_ms = now_ms()?;
        let initial_commit_deadline_ms = issued_at_ms
            .checked_add(REQUEST_LIFETIME_MS)
            .ok_or(Error::InvalidData)?
            .min(policy.policy_expires_at_ms);
        let request = PendingBirthRequest {
            version: 1,
            operation_id: self.anchor.operation_id().into(),
            generation_instance_id: self.anchor.generation_instance_id().into(),
            native_birth_digest: self.anchor.birth_digest().into(),
            original_terms_digest: self.anchor.original_policy_terms_digest().into(),
            original_target_digest: canonical(
                "wholepact:pending-birth-target:v1",
                &self.anchor.intent.original_target,
            )?,
            disclosure,
            policy,
            issued_at_ms,
            initial_commit_deadline_ms,
        };
        self.anchor.require_exact_pending_request(&request)?;
        request
            .require_initial_commit_time(issued_at_ms)
            .map_err(|_| Error::ReviewMismatch)?;
        let source = owner.native().binding();
        let review_digest = canonical(
            "wholepact:native-pending-owner-request:v1",
            &(
                request.digest().map_err(|_| Error::InvalidData)?,
                owner.native().principal_id(),
                owner.native().measurement(),
            ),
        )?;
        Ok(PreparedPendingOwnerRequest {
            pending: Arc::clone(self),
            source,
            request,
            review_digest,
            created: Instant::now(),
        })
    }
}
impl PreparedPendingOwnerRequest {
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.review_digest
    }
    pub(crate) fn review_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.request).map_err(|_| Error::InvalidData)
    }
    fn check(&self, owner: &PendingAccountNativeAuthority) -> Result<()> {
        owner.check_current()?;
        self.source.check_current()?;
        if self.created.elapsed() >= REVIEW_LIFETIME || self.source != owner.native().binding() {
            return Err(Error::ReviewMismatch);
        }
        self.pending.require_original_request_target()?;
        self.pending.require_no_staged_owner_request()?;
        self.pending
            .anchor
            .require_exact_pending_request(&self.request)?;
        self.request
            .require_initial_commit_time(now_ms()?)
            .map_err(|_| Error::ReviewMismatch)
    }
    /// Consumes the genuine exact local native decision. Durable write occurs
    /// under that owner's invalidation lease; failure returns no retained handle.
    pub(crate) fn retain(
        self,
        decision: NativeDecision,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<RetainedPendingOwnerRequest> {
        self.check(owner)?;
        if decision.binding() != &self.source || decision.reviewed_digest() != self.review_digest {
            return Err(Error::ReviewMismatch);
        }
        let plain =
            Zeroizing::new(serde_json::to_vec(&self.request).map_err(|_| Error::InvalidData)?);
        let encrypted = vault::encrypt(
            &self.pending.encryption_key,
            &self.pending.request_domain()?,
            &plain,
        )?;
        if encrypted.len() > MAX_REQUEST {
            return Err(Error::InvalidData);
        }
        // Flock excludes another vault opener, not concurrent borrows of this
        // same owner. Serialize check-and-publish within the actual vault too.
        let _request_publication = self
            .pending
            .request_publication
            .lock()
            .map_err(|_| Error::Locked)?;
        let _publication = self.source.publication_lease()?;
        self.check(owner)?;
        // Directory lock excludes supported writers/replacement. This is not a
        // guarantee against a malicious same-user process bypassing that lock.
        if self.pending._directory.exists(REQUEST_FILE)? {
            return Err(Error::ReviewMismatch);
        }
        self.pending._directory.write(REQUEST_FILE, &encrypted)?;
        self.pending._directory.sync_all_files()?;
        let retained = self
            .pending
            .retained_owner_request()?
            .ok_or(Error::RecoveryRequired)?;
        if retained.request != self.request {
            return Err(Error::ReviewMismatch);
        }
        Ok(retained)
    }
}
fn now_ms() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidData)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::InvalidData)
}
