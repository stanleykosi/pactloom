//! A private invitation is a read-only agreement preview. It never establishes
//! wallet control, recipient ownership, membership approval or spending authority.
use crate::{
    prepare_export, types::*, ExportRequest, PreparedExport, ReceivedArtifact, TransportPublicKey,
};
use serde::{Deserialize, Serialize};

const FIELD: &str = "private_invitation_v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationRole {
    Contributor,
    Sponsor,
    Recipient,
    Reviewer,
}

/// Only deliberately selected review text and fingerprints belong here. No key,
/// witness, raw transaction, executable attachment, URL or automatic fetch field
/// exists. Trusted source adapters must still keep secrets out of free text.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateInvitation {
    pub schema_version: u16,
    pub invitation_id: String,
    pub organizer_key_fingerprint: String,
    pub invited_participant_id: String,
    pub agreement_manifest_digest: String,
    pub offered_roles: Vec<InvitationRole>,
    pub purpose: String,
    pub recipient_summary: String,
    pub fee_summary: String,
    pub visibility_summary: String,
    pub coordination_deadline: Timestamp,
}
impl PrivateInvitation {
    fn validate(&self, preview: &DisclosurePreview) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TransportError::UnsupportedVersion);
        }
        if preview.context.artifact_kind != ArtifactKind::Invitation {
            return Err(TransportError::WrongContext);
        }
        validate_hex(&self.invitation_id, 16)?;
        validate_hex(&self.agreement_manifest_digest, 32)?;
        validate_hex(&self.organizer_key_fingerprint, 32)?;
        validate_id(&self.invited_participant_id)?;
        if self.invited_participant_id != preview.context.recipient_id {
            return Err(TransportError::WrongRecipient);
        }
        if self.organizer_key_fingerprint != preview.sender_key_fingerprint {
            return Err(TransportError::Authentication);
        }
        if self.offered_roles.is_empty()
            || self.offered_roles.len() > 4
            || self
                .offered_roles
                .windows(2)
                .any(|roles| roles[0] >= roles[1])
        {
            return Err(TransportError::Malformed);
        }
        for text in [
            &self.purpose,
            &self.recipient_summary,
            &self.fee_summary,
            &self.visibility_summary,
        ] {
            validate_text(text)?;
        }
        if self.coordination_deadline.unix_seconds() < preview.order.expires_at.unix_seconds() {
            return Err(TransportError::InvalidTime);
        }
        Ok(())
    }
}

pub fn prepare_invitation(
    request: ExportRequest,
    invitation: PrivateInvitation,
    sender: &TransportPublicKey,
    recipient: &TransportPublicKey,
    now: &Timestamp,
) -> Result<PreparedExport> {
    let field = DisclosureField::new(FIELD, encode(&invitation)?)?;
    let prepared = prepare_export(request, vec![field], sender, recipient, now)?;
    invitation.validate(prepared.preview())?;
    Ok(prepared)
}

pub struct InvitationReview {
    invitation: PrivateInvitation,
    issued_at: Timestamp,
    expires_at: Timestamp,
}
impl InvitationReview {
    pub fn is_currently_valid(&self, now: &Timestamp) -> bool {
        now.unix_seconds() >= self.issued_at.unix_seconds()
            && now.unix_seconds() < self.expires_at.unix_seconds()
    }
    pub fn invitation(&self) -> &PrivateInvitation {
        &self.invitation
    }
    pub fn is_read_only(&self) -> bool {
        true
    }
    pub fn authorization_allowed(&self) -> bool {
        false
    }
    pub fn wallet_control_verified(&self) -> bool {
        false
    }
    pub fn recipient_ownership_verified(&self) -> bool {
        false
    }
}

/// Requires a successfully authenticated receipt, checks its single supported
/// payload and binding, and returns inert read-only review data. Callers displaying
/// recovered invitations must also show historical/expired status from recovery.
pub fn review_invitation(artifact: &ReceivedArtifact) -> Result<InvitationReview> {
    let fields = artifact.fields();
    if fields.len() != 1 || fields[0].name() != FIELD {
        return Err(TransportError::Malformed);
    }
    let invitation: PrivateInvitation = parse(fields[0].bytes())?;
    invitation.validate(artifact.preview())?;
    Ok(InvitationReview {
        invitation,
        issued_at: artifact.preview().order.issued_at.clone(),
        expires_at: artifact.preview().order.expires_at.clone(),
    })
}
