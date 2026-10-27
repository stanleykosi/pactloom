//! Return-only fresh native owners. Neither wrapper can be deserialized,
//! cloned, constructed from a receipt, or unwrapped into an old action owner.
use super::{NativeDecision, NativePublicationLease};
use super::financial_authority_v1::{FinancialReadLeaseV1, FinancialReturnActionV1,
    FinancialNativeRevocationV1, PreparedFinancialReviewV1};
use crate::{Error, Result};
use crate::native_peer::PeerProcess;
use crate::authority_bridge::financial_continuation_v1::DurableFinancialResultRequestV2;
use std::time::Instant;

pub(crate) struct DurableFinancialResultReadV2(FinancialReadLeaseV1);
pub(crate) struct DurableFinancialResultReturnV2(FinancialReturnActionV1);

impl DurableFinancialResultReadV2 {
    pub(in crate::native_ui) fn approve(
        prepared: PreparedFinancialReviewV1, decision: NativeDecision,
        request: &DurableFinancialResultRequestV2, source: &str, peer: &PeerProcess,
    ) -> Result<Self> {
        let value = Self(prepared.approve_read(decision)?);
        value.check_scope(source, request, peer)?;
        Ok(value)
    }
    pub(crate) fn check_scope(&self, source: &str, request: &DurableFinancialResultRequestV2, peer: &PeerProcess) -> Result<()> {
        self.0.check_source(source)?;
        peer.check_alive()?;
        let expected = request.read_review_digest(source, peer.instance()).map_err(|_| Error::ReviewMismatch)?;
        if self.0.terms_digest() != expected { return Err(Error::ReviewMismatch); }
        self.0.check_source(source)
    }
}
impl DurableFinancialResultReturnV2 {
    pub(in crate::native_ui) fn approve(
        prepared: PreparedFinancialReviewV1, decision: NativeDecision,
        request: &DurableFinancialResultRequestV2, source: &str, peer: &PeerProcess,
        signature_set_digest: &str,
    ) -> Result<Self> {
        let value = Self(prepared.approve_return(decision)?);
        value.check_scope(source, request, peer, signature_set_digest)?;
        Ok(value)
    }
    pub(crate) fn check_scope(&self, source: &str, request: &DurableFinancialResultRequestV2, peer: &PeerProcess, signature_set_digest: &str) -> Result<()> {
        self.0.check_source(source)?;
        peer.check_alive()?;
        let expected = request.return_review_digest(source, peer.instance(), signature_set_digest).map_err(|_| Error::ReviewMismatch)?;
        if self.0.terms_digest() != expected { return Err(Error::ReviewMismatch); }
        self.0.check_source(source)
    }
}
macro_rules! scoped_accessors {
    ($name:ident) => { impl $name {
        pub(crate) fn check_current(&self) -> Result<()> { self.0.check_current() }
        pub(crate) fn check_source(&self, source: &str) -> Result<()> { self.0.check_source(source) }
        pub(crate) fn terms_digest(&self) -> &str { self.0.terms_digest() }
        pub(crate) fn expires_at_unix_ms(&self) -> u64 { self.0.expires_at_unix_ms() }
        pub(crate) fn original_deadline(&self) -> Result<Instant> { self.0.binding().bounded_deadline() }
        pub(crate) fn publication_lease(&self) -> Result<NativePublicationLease<'_>> { self.0.publication_lease() }
        pub(crate) fn revocation(&self) -> FinancialNativeRevocationV1 { self.0.revocation() }
    }};
}
scoped_accessors!(DurableFinancialResultReadV2);
scoped_accessors!(DurableFinancialResultReturnV2);
