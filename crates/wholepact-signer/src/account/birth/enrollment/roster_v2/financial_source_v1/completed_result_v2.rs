//! A new, result-only native opening of the exact completed original.
//! No writer, wallet, acquisition or signing API escapes this closed wrapper.
//! Historical result bytes survive; every new disclosure needs fresh authority.
use super::*;
use crate::authority_bridge::{BridgeError, protocol::RetainedAuthorizationResult};
use crate::authority_bridge::financial_continuation_v1::{
    DurableFinancialResultRequestV2, audited_signature_set_digest_v2,
};
use crate::consent_journal::{AuditedDurableFinancialResultRowsV2, OriginalAuthorizationEvidence};
use crate::native_peer::PeerProcess;
use crate::native_ui::durable_result_authority_v2::{
    DurableFinancialResultReadV2, DurableFinancialResultReturnV2,
};
use wholepact_authority::OwnerControlRequest;
use std::sync::atomic::{AtomicBool, Ordering};

fn bridge_error(error: BridgeError) -> Error {
    match error {
        BridgeError::Uncertain => Error::Uncertain,
        BridgeError::Permission => Error::Locked,
        _ => Error::ReviewMismatch,
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl PreparedOriginalFinancialSourceV1 {
    /// Actual V1 original20 opening composed with the exact V2 selection kernel.
    /// Not full V2 UI-opener proof and not a fresh Witness-ledger reconciliation.
    pub(crate) fn audit_started_only_for_qualification_v2(
        &self,
        expected_account: &str,
        expected_authorization: &str,
    ) -> Result<crate::consent_journal::FinancialStartedOnlyAuditV2> {
        self.check_immutable_original_v1()?;
        self.check_custody()?;
        let before = self.financial_journal()?.audit_started_only_rows_for_qualification_v2(
            &*self.financial_binding()?, expected_account, expected_authorization,
        ).map_err(bridge_error)?;
        match self.financial_journal()?.durable_result_selection_v2(&*self.financial_binding()?) {
            Err(BridgeError::Uncertain) => {},
            _ => return Err(Error::ReviewMismatch),
        }
        let after = self.financial_journal()?.audit_started_only_rows_for_qualification_v2(
            &*self.financial_binding()?, expected_account, expected_authorization,
        ).map_err(bridge_error)?;
        if before != after { return Err(Error::ReviewMismatch); }
        self.check_custody()?;
        self.check_immutable_original_v1()?;
        Ok(after)
    }
}

pub(crate) struct RecoveredFinancialResultSourceV2 {
    // The original source owns actual encrypted/file/directory exclusion. It
    // is deliberately private: callers cannot recover old financial actions.
    original: PreparedOriginalFinancialSourceV1,
    selection: DurableFinancialResultRequestV2,
    review_scope: String,
    revoked: AtomicBool,
}

impl RecoveredFinancialResultSourceV2 {
    pub(crate) fn open_original20(
        root: &Path,
        password: &[u8],
        owner: Arc<PendingAccountNativeAuthority>,
    ) -> Result<Self> {
        let original = PreparedOriginalFinancialSourceV1::open_original20(root, password, owner)?;
        original.check_immutable_original_v1()?;
        let (selection, review_scope) = original.financial_journal()?
            .durable_result_selection_v2(&*original.financial_binding()?)
            .map_err(bridge_error)?;
        original.check_custody()?;
        original.check_immutable_original_v1()?;
        Ok(Self { original, selection, review_scope, revoked: AtomicBool::new(false) })
    }
    pub(crate) fn identity_digest(&self) -> &str { self.original.identity_digest() }
    pub(crate) fn original_ceiling_ms(&self) -> u64 { self.original.original_ceiling_ms() }
    pub(crate) fn original_deadline(&self) -> Instant { self.original.original_deadline() }
    /// Denial-only UI cancellation. Never creates or refreshes any permission.
    pub(crate) fn revoke_v2(&self) { self.revoked.store(true, Ordering::Release); }
    pub(crate) fn check_custody(&self) -> Result<()> {
        if self.revoked.load(Ordering::Acquire) { return Err(Error::Locked); }
        self.original.check_immutable_original_v1()?;
        self.original.check_custody()?;
        self.original.check_immutable_original_v1()?;
        if self.revoked.load(Ordering::Acquire) { return Err(Error::Locked); }
        Ok(())
    }
    /// An inert exact selector, not a result, recipient approval or saved grant.
    pub(crate) fn selection_v2(&self) -> Result<DurableFinancialResultRequestV2> {
        self.check_custody()?;
        Ok(self.selection.clone())
    }
    pub(crate) fn review_scope_v2(&self) -> Result<String> {
        self.check_custody()?;
        Ok(self.review_scope.clone())
    }
    pub(crate) fn read_for_return_v2(
        self: &Arc<Self>,
        request: &DurableFinancialResultRequestV2,
        peer: &PeerProcess,
        read: &DurableFinancialResultReadV2,
    ) -> Result<AuditedFinancialResultSnapshotV2> {
        self.check_custody()?;
        if request != &self.selection { return Err(Error::ReviewMismatch); }
        read.check_scope(self.identity_digest(), request, peer)?;
        peer.check_alive()?;
        let rows = self.original.financial_journal()?.read_durable_result_v2(
            &*self.original.financial_binding()?, request, peer, read,
        ).map_err(bridge_error)?;
        if rows.selection != *request || rows.pin.result_digest() != request.result_digest {
            return Err(Error::ReviewMismatch);
        }
        let signature_set_digest = audited_signature_set_digest_v2(
            &rows.original, &rows.result, &rows.continuation, &request.request,
        ).map_err(bridge_error)?;
        read.check_scope(self.identity_digest(), request, peer)?;
        let snapshot = AuditedFinancialResultSnapshotV2 {
            source: Arc::clone(self), peer: peer.clone(), rows, signature_set_digest,
        };
        snapshot.check_custody_v2()?;
        read.check_scope(self.identity_digest(), request, peer)?;
        Ok(snapshot)
    }
}

/// Inert custody after an actual full Read. It does not carry the Read deadline
/// into a later grant and cannot export exact result bytes by itself.
pub(crate) struct AuditedFinancialResultSnapshotV2 {
    source: Arc<RecoveredFinancialResultSourceV2>,
    peer: PeerProcess,
    rows: AuditedDurableFinancialResultRowsV2,
    signature_set_digest: String,
}
impl AuditedFinancialResultSnapshotV2 {
    pub(crate) fn request(&self) -> &DurableFinancialResultRequestV2 { &self.rows.selection }
    pub(crate) fn source_identity_digest(&self) -> &str { self.source.identity_digest() }
    pub(crate) fn original_deadline(&self) -> Instant { self.source.original_deadline() }
    pub(crate) fn original_ceiling_ms(&self) -> u64 { self.source.original_ceiling_ms() }
    pub(crate) fn peer(&self) -> &PeerProcess { &self.peer }
    pub(crate) fn signature_set_digest(&self) -> &str { &self.signature_set_digest }
    pub(crate) fn check_custody_v2(&self) -> Result<()> {
        self.source.check_custody()?;
        self.peer.check_alive()?;
        self.source.original.financial_journal()?.check_financial_return_pin_v1(
            &*self.source.original.financial_binding()?, &self.rows.pin,
        )?;
        if self.rows.selection != self.source.selection
            || self.rows.pin.original_host_instance() != self.rows.selection.original_host_process_instance
            || self.rows.pin.result_digest() != self.rows.selection.result_digest
        { return Err(Error::ReviewMismatch); }
        self.peer.check_alive()?;
        self.source.check_custody()
    }
    /// Private bridge interpretation only, with the genuine fresh Read still
    /// held. The network may receive its reviewed preview, never exact outbox.
    pub(crate) fn evidence_for_preview_v2<'a>(
        &'a self, read: &DurableFinancialResultReadV2,
    ) -> Result<(&'a OriginalAuthorizationEvidence, &'a RetainedAuthorizationResult, &'a OwnerControlRequest)> {
        read.check_scope(self.source.identity_digest(), &self.rows.selection, &self.peer)?;
        self.check_custody_v2()?;
        read.check_scope(self.source.identity_digest(), &self.rows.selection, &self.peer)?;
        Ok((&self.rows.original, &self.rows.result, &self.rows.continuation))
    }
    pub(crate) fn bind_return_v2(
        self,
        action: DurableFinancialResultReturnV2,
        peer: PeerProcess,
    ) -> Result<RecipientBoundFinancialResultV2> {
        self.check_custody_v2()?;
        self.peer.same_live_process(&peer)?;
        action.check_scope(self.source.identity_digest(), &self.rows.selection, &peer, &self.signature_set_digest)?;
        let bound = RecipientBoundFinancialResultV2 { snapshot: self, action };
        bound.check_current()?;
        Ok(bound)
    }
}

/// Only this owner consumes fresh exact Return permission. The new recipient
/// is an actual current pidfd and never replaces the historical Host identity.
pub(crate) struct RecipientBoundFinancialResultV2 {
    snapshot: AuditedFinancialResultSnapshotV2,
    action: DurableFinancialResultReturnV2,
}
impl RecipientBoundFinancialResultV2 {
    pub(crate) fn request(&self) -> &DurableFinancialResultRequestV2 { self.snapshot.request() }
    pub(crate) fn peer(&self) -> &PeerProcess { self.snapshot.peer() }
    pub(crate) fn original_deadline(&self) -> Result<Instant> {
        Ok(self.snapshot.original_deadline().min(self.action.original_deadline()?))
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        self.action.check_scope(self.snapshot.source.identity_digest(), self.request(), self.peer(), self.snapshot.signature_set_digest())?;
        self.snapshot.check_custody_v2()?;
        self.action.check_scope(self.snapshot.source.identity_digest(), self.request(), self.peer(), self.snapshot.signature_set_digest())
    }
    pub(crate) fn evidence_for_return_v2(&self)
        -> Result<(&OriginalAuthorizationEvidence, &RetainedAuthorizationResult, &OwnerControlRequest)>
    {
        self.check_current()?;
        Ok((&self.snapshot.rows.original, &self.snapshot.rows.result, &self.snapshot.rows.continuation))
    }
}
