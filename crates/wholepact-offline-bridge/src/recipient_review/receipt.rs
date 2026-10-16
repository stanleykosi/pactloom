//! Exact authenticated history observations, never permission or setup authority.
use super::*;

/// Persistence callback error only; it conveys no authority or authentication.
pub type OfflineReceiptPersistenceError = TransportError;

/// Can only be made by exact authenticated import/recovery in this module tree.
/// A callback observation precedes inbox commit; it does NOT prove acceptance.
pub struct AuthenticatedOfflineReviewReceipt {
    account_id: String,
    authorization_id: String,
    owner_setup_digest: String,
    terms_digest: String,
    package_digest: String,
    preview: DisclosurePreview,
    envelope_digest: String,
    content_digest: String,
}
impl AuthenticatedOfflineReviewReceipt {
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn authorization_id(&self) -> &str {
        &self.authorization_id
    }
    pub fn owner_setup_digest(&self) -> &str {
        &self.owner_setup_digest
    }
    pub fn terms_digest(&self) -> &str {
        &self.terms_digest
    }
    pub fn package_digest(&self) -> &str {
        &self.package_digest
    }
    pub fn preview(&self) -> &DisclosurePreview {
        &self.preview
    }
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
}

pub(super) fn from_artifact(
    artifact: &ReceivedArtifact,
    setup: &OwnerEstablishedOfflineSetup,
    expected: &RetainedOfflineReviewInputs,
) -> Result<AuthenticatedOfflineReviewReceipt> {
    Ok(AuthenticatedOfflineReviewReceipt {
        account_id: expected.terms.account_id.clone(),
        authorization_id: expected.terms.authorization_id.clone(),
        owner_setup_digest: setup.owner_setup_digest.clone(),
        terms_digest: expected
            .terms
            .terms_digest()
            .map_err(|_| TransportError::Malformed)?,
        package_digest: expected.terms.review_package_digest.clone(),
        preview: artifact.preview().clone(),
        envelope_digest: artifact.envelope_digest().into(),
        content_digest: artifact.content_digest().into(),
    })
}

/// Read-only accepted history, independently recovered from concrete inbox.
/// Never converted to a fresh review, native consent or key-use permission.
pub struct RecoveredOfflineReviewReceipt {
    receipt: AuthenticatedOfflineReviewReceipt,
}
impl RecoveredOfflineReviewReceipt {
    pub fn receipt(&self) -> &AuthenticatedOfflineReviewReceipt {
        &self.receipt
    }
}

/// Exact retry after inbox commit but before signer receipt-link commit.
/// Uses independent original expectations and re-runs the full domain validator.
/// Expired ciphertext may remain historical evidence; no current review results.
pub fn recover_offline_review_receipt(
    signer_secret: &TransportSecret,
    setup: &OwnerEstablishedOfflineSetup,
    expected: &RetainedOfflineReviewInputs,
    sequence: u64,
    expected_envelope_digest: &str,
    expected_content_digest: &str,
    inbox: &SqliteReplayLedger,
) -> Result<Option<RecoveredOfflineReviewReceipt>> {
    check_setup(setup, expected)?;
    if inbox.protection() != MailboxProtection::Encrypted
        || inbox.database_identity()? != setup.inbox_identity
        || signer_secret.public_key()? != setup.signer_key
    {
        return Err(TransportError::Authentication);
    }
    let context = review_context(setup, &expected.terms);
    let Some(retained) = inbox.retained_for_context(&context, sequence)? else {
        return Ok(None);
    };
    let recovered = recover_received(&retained, signer_secret, &setup.source_key, &context)?;
    let artifact = recovered.artifact();
    if artifact.envelope_digest() != expected_envelope_digest
        || artifact.content_digest() != expected_content_digest
    {
        return Err(TransportError::WrongContext);
    }
    let _display = Zeroizing::new(inspect_fields(artifact.fields(), setup, expected)?);
    Ok(Some(RecoveredOfflineReviewReceipt {
        receipt: from_artifact(artifact, setup, expected)?,
    }))
}

/// Concrete transport resources, not account enrollment or approval authority.
/// The already-existing secret/inbox must match the owner-established setup.
pub struct OfflineReviewChannel<'a> {
    secret: &'a TransportSecret,
    inbox: &'a mut SqliteReplayLedger,
}
impl<'a> OfflineReviewChannel<'a> {
    pub fn new(secret: &'a TransportSecret, inbox: &'a mut SqliteReplayLedger) -> Result<Self> {
        if inbox.protection() != MailboxProtection::Encrypted {
            return Err(TransportError::AuthorityUnavailable);
        }
        Ok(Self { secret, inbox })
    }
    pub fn import_recording(
        &mut self,
        bytes: &[u8],
        setup: &OwnerEstablishedOfflineSetup,
        expected: &RetainedOfflineReviewInputs,
        now_unix_seconds: i64,
        record: impl FnOnce(&AuthenticatedOfflineReviewReceipt) -> Result<()>,
    ) -> Result<OfflineReviewInspection> {
        let envelope = EncryptedEnvelope::from_bytes(bytes.to_vec())?;
        let now = Timestamp::from_unix_seconds(now_unix_seconds)?;
        import_offline_review_package_recording(
            &envelope,
            self.secret,
            setup,
            expected,
            &now,
            self.inbox,
            record,
        )
    }
    pub fn recover_receipt(
        &self,
        setup: &OwnerEstablishedOfflineSetup,
        expected: &RetainedOfflineReviewInputs,
        sequence: u64,
        envelope_digest: &str,
        content_digest: &str,
    ) -> Result<Option<RecoveredOfflineReviewReceipt>> {
        recover_offline_review_receipt(
            self.secret,
            setup,
            expected,
            sequence,
            envelope_digest,
            content_digest,
            self.inbox,
        )
    }
}

impl OfflineReviewChannel<'_> {
    /// Re-run exact inspection after a long round trip in the same process.
    /// The next native final decision remains fresh and separate. A restart loses
    /// this monotonic continuation and must use the still-unavailable restart path.
    pub fn reinspect_in_process(
        &self,
        previous: &OfflineReviewInspection,
        setup: &OwnerEstablishedOfflineSetup,
        expected: &RetainedOfflineReviewInputs,
    ) -> Result<OfflineReviewInspection> {
        reinspection::reinspect_in_process(previous, self.secret, setup, expected, self.inbox)
    }
}
