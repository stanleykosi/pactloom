//! Explicit owner-authenticated continuation after the original construction
//! transport was permanently fenced. This never revives that general MAC key,
//! creates a writer session, changes its expiry, or authorizes another original.
use crate::{
    born_offline_construction_v1::{
        BornOfflineConstructionLinkV1, BornOfflineConstructionOriginV1,
    },
    born_offline_enrollment_v1::BornOfflineEnrollmentV1,
    *,
};
use serde::{Deserialize, Serialize};

/// Inert signed enrollment scope. The original owner certificate is pinned by
/// the enclosing enrollment and must be independently approved by the actual
/// original witness owner. History alone cannot install this purpose.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BornOfflineOwnerContinuationV1 {
    pub version: u16,
    pub construction_reservation_operation_id: String,
    pub construction_consume_operation_id: String,
    pub construction_origin_digest: String,
    pub construction_transport_credential_id: String,
}
impl BornOfflineOwnerContinuationV1 {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(AuthorityError::UnsupportedVersion);
        }
        id(&self.construction_reservation_operation_id)?;
        id(&self.construction_consume_operation_id)?;
        hash(&self.construction_origin_digest)?;
        if self.construction_reservation_operation_id == self.construction_consume_operation_id {
            return Err(AuthorityError::InvalidBinding);
        }
        hash(&self.construction_transport_credential_id)
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest("wholepact:born-offline-owner-continuation:v1", self)
    }
    pub fn validate_origin(
        &self,
        enrollment: &BornOfflineEnrollmentV1,
        original: &BornOfflineConstructionOriginV1,
    ) -> Result<()> {
        self.validate()?;
        original.validate()?;
        if self.construction_origin_digest != original.digest()?
            || self.construction_reservation_operation_id
                != original.reservation.request.construction.operation_id
            || self.construction_consume_operation_id != original.consumed.request.operation_id
            || original.transport_credential_id.as_deref()
                != Some(self.construction_transport_credential_id.as_str())
            || original.reservation.session != enrollment.original_writer_session
            || enrollment.expected_head.sequence < original.consumed.snapshot.head.sequence
            || enrollment.issued_at_ms < original.consumed.consumed_at_ms
            || enrollment.policy.expires_at_ms > original.reservation.construction_expires_at_ms
            || enrollment.first_commit_deadline_ms > original.reservation.construction_expires_at_ms
        {
            return Err(AuthorityError::InvalidBinding);
        }
        Ok(())
    }
}
impl BornOfflineEnrollmentV1 {
    /// Exact authenticated transport identity, distinct from historical writer
    /// lineage. Only the purpose-specific born route may use this selection.
    pub(crate) fn born_transport_certificate_v1(&self) -> &str {
        if self.owner_continuation.is_some() {
            &self.owner_certificate_digest
        } else {
            &self.original_writer_session.writer_certificate_digest
        }
    }
    pub(crate) fn born_event_writer_session_v1(&self) -> Option<String> {
        self.owner_continuation
            .is_none()
            .then(|| self.original_writer_session.session_id.clone())
    }
    pub(crate) fn require_born_construction_scope_v1(
        &self,
        link: &BornOfflineConstructionLinkV1,
    ) -> Result<()> {
        if let Some(owner) = &self.owner_continuation {
            owner.validate()?;
            if owner.construction_reservation_operation_id != link.reservation_operation_id
                || owner.construction_consume_operation_id != link.consume_operation_id
            {
                return Err(AuthorityError::Permission);
            }
        }
        Ok(())
    }
}
impl policy::Ledger {
    /// The legacy original-writer origin keeps its old fence. The explicit new
    /// owner purpose instead REQUIRES the exact permanent old-key fence and
    /// consumed handoff membership, without removing or bypassing that fence.
    pub(crate) fn require_born_transport_lineage_v1(
        &self,
        enrollment: &BornOfflineEnrollmentV1,
    ) -> Result<()> {
        let Some(owner) = &enrollment.owner_continuation else {
            return self.require_unfenced_transport(&enrollment.original_writer_session.session_id);
        };
        enrollment.validate_original_policy(&self.policy)?;
        let original = self.born_offline_construction_origin_by_operations_v1(
            &owner.construction_reservation_operation_id,
            &owner.construction_consume_operation_id,
        )?;
        owner.validate_origin(enrollment, &original)?;
        let credential =
            self.construction_transport_credential(&owner.construction_transport_credential_id)?;
        credential.validate()?;
        credential
            .pending_grant
            .grant
            .authorization
            .verify(&enrollment.owner_certificate_digest)?;
        let fence = self
            .snapshot
            .transport_fences
            .as_ref()
            .ok_or(AuthorityError::Permission)?;
        if fence.version != 1
            || !fence
                .fenced_session_ids
                .contains(&enrollment.original_writer_session.session_id)
            || credential.authorization().original_session != enrollment.original_writer_session
            || credential.authorization().invocation_digest
                != original.reservation.request.invocation_digest()?
            || credential.claimed_head.sequence >= original.reservation.snapshot.head.sequence
        {
            return Err(AuthorityError::Permission);
        }
        Ok(())
    }
}

/// Wire authentication selection only. Owner-origin evidence is not a MAC and
/// never masquerades as one. The server authenticates the actual TLS peer and
/// the exact native-installed enrollment before this variant has any meaning.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "origin", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum BornOfflineTransportAuthenticationV1 {
    OriginalWriterSessionV1 {
        proof: protocol::WriterSessionProof,
    },
    OriginalOwnerContinuationV1 {
        enrollment_digest: String,
        continuation_digest: String,
    },
}
impl BornOfflineTransportAuthenticationV1 {
    #[cfg(any(test, all(feature = "born-offline-witness-owner", target_os = "linux")))]
    pub(crate) fn select_original_proof<'a>(
        &'a self,
        enrollment: &BornOfflineEnrollmentV1,
        actual_tls_peer: &str,
    ) -> Result<Option<&'a protocol::WriterSessionProof>> {
        if actual_tls_peer != enrollment.born_transport_certificate_v1() {
            return Err(AuthorityError::Authentication);
        }
        match (self, &enrollment.owner_continuation) {
            (Self::OriginalWriterSessionV1 { proof }, None)
                if proof.session_id == enrollment.original_writer_session.session_id =>
            {
                Ok(Some(proof))
            }
            (
                Self::OriginalOwnerContinuationV1 {
                    enrollment_digest,
                    continuation_digest,
                },
                Some(origin),
            ) if *enrollment_digest == enrollment.digest()?
                && *continuation_digest == origin.digest()? =>
            {
                Ok(None)
            }
            _ => Err(AuthorityError::Authentication),
        }
    }
}
