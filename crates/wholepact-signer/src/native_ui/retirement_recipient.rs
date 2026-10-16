//! Unconnected evidence-only recipient owner. Only an already authenticated
//! concrete peer can construct the production owner. No wire token, claimed
//! digest, callback, grant creation or IPC activation can mint this authority.
#![allow(dead_code)] // Staged adapter; deliberately absent from runtime dispatch.
use super::{
    NativeAuthority, NativeAuthorityBinding, retirement_destination::RecoveryDestinationRequest,
};
use crate::{
    Error, Result,
    ipc::{AuthenticatedPeer, PairScope},
};
use serde::Serialize;

#[derive(Clone, PartialEq, Eq, Serialize)]
struct RecipientBinding {
    grant_id: String,
    channel_digest: String,
    key_digest: String,
    generation: u64,
    process_instance: String,
    uid: u32,
    pid: u32,
    application_label: String,
    scope: PairScope,
    native_entry: String,
}
#[derive(Clone)]
enum RecipientOwner {
    Peer(Box<AuthenticatedPeer>),
    // No production fallback: unit-test-only lifecycle fixtures neither create
    // an AuthenticatedPeer nor claim to qualify kernel process authentication.
    #[cfg(all(test, feature = "synthetic-qualification"))]
    Synthetic {
        native: NativeAuthorityBinding,
        current: std::sync::Arc<std::sync::atomic::AtomicBool>,
        expires: std::time::Instant,
    },
}
#[derive(Clone)]
pub(super) struct RetirementEvidenceRecipient {
    binding: RecipientBinding,
    digest: String,
    owner: RecipientOwner,
}
impl RetirementEvidenceRecipient {
    pub(super) fn from_peer(peer: AuthenticatedPeer) -> Result<Self> {
        peer.check_current()?;
        let binding = RecipientBinding {
            grant_id: peer.grant_id.clone(),
            channel_digest: peer.channel_digest.clone(),
            key_digest: peer.key_digest.clone(),
            generation: peer.generation,
            process_instance: peer.peer.instance().into(),
            uid: peer.peer.uid(),
            pid: peer.peer.pid(),
            application_label: peer.label.clone(),
            scope: peer.scope.clone(),
            native_entry: peer.native_origin.entry_digest().into(),
        };
        let digest = binding_digest(&binding)?;
        Ok(Self {
            binding,
            digest,
            owner: RecipientOwner::Peer(Box::new(peer)),
        })
    }
    /// Synthetic restriction fixture only. This is not an AuthenticatedPeer,
    /// authenticated reply, transport admission, or attended native consent.
    #[cfg(all(test, feature = "synthetic-qualification"))]
    pub(super) fn synthetic_for_session_test(
        source_account_id: String,
        source_native: &NativeAuthority,
        expires: std::time::Instant,
    ) -> Result<Self> {
        let binding = RecipientBinding {
            grant_id: "12".repeat(32),
            channel_digest: "23".repeat(32),
            key_digest: "34".repeat(32),
            generation: 7,
            process_instance: "45".repeat(32),
            uid: 1000,
            pid: 1234,
            application_label: "synthetic-session-evidence-reader".into(),
            scope: crate::ipc::PairScope {
                account_id: source_account_id,
                agreement_id: "synthetic-retirement".into(),
                participant_id: "synthetic-owner".into(),
                manifest_digest: "56".repeat(32),
                history_read: false,
                authorization_export: false,
                preconstruction_export: false,
            },
            native_entry: source_native.binding().entry_digest().into(),
        };
        Ok(Self {
            digest: binding_digest(&binding)?,
            binding,
            owner: RecipientOwner::Synthetic {
                native: source_native.binding(),
                current: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
                expires,
            },
        })
    }
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }
    pub(super) fn grant_id(&self) -> &str {
        &self.binding.grant_id
    }
    pub(super) fn scope(&self) -> &PairScope {
        &self.binding.scope
    }
    pub(super) fn deadline(&self) -> std::time::Instant {
        match &self.owner {
            RecipientOwner::Peer(peer) => peer.deadline(),
            #[cfg(all(test, feature = "synthetic-qualification"))]
            RecipientOwner::Synthetic { expires, .. } => *expires,
        }
    }
    fn native(&self) -> &NativeAuthorityBinding {
        match &self.owner {
            RecipientOwner::Peer(peer) => &peer.native_origin,
            #[cfg(all(test, feature = "synthetic-qualification"))]
            RecipientOwner::Synthetic { native, .. } => native,
        }
    }
    pub(super) fn check_current(&self) -> Result<()> {
        match &self.owner {
            RecipientOwner::Peer(peer) => peer.check_current(),
            #[cfg(all(test, feature = "synthetic-qualification"))]
            RecipientOwner::Synthetic {
                native,
                current,
                expires,
            } => {
                native.check_current()?;
                if !current.load(std::sync::atomic::Ordering::Acquire)
                    || std::time::Instant::now() >= *expires
                {
                    return Err(Error::Authentication);
                }
                Ok(())
            }
        }
    }
    pub(super) fn check_source(
        &self,
        native: &NativeAuthority,
        request: &RecoveryDestinationRequest,
    ) -> Result<()> {
        self.check_request(request)?;
        if self.native() != &native.binding() {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(super) fn check_request(&self, request: &RecoveryDestinationRequest) -> Result<()> {
        self.check_current()?;
        if request.local_recipient != self.binding.grant_id
            || request.source_account_id != self.binding.scope.account_id
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(super) fn require_same(&self, other: &Self) -> Result<()> {
        self.check_current()?;
        other.check_current()?;
        if self.binding != other.binding || self.digest != other.digest {
            return Err(Error::Authentication);
        }
        match (&self.owner, &other.owner) {
            (RecipientOwner::Peer(a), RecipientOwner::Peer(b)) => a.require_same_grant(b),
            #[cfg(all(test, feature = "synthetic-qualification"))]
            (
                RecipientOwner::Synthetic {
                    native: a,
                    current: ac,
                    expires: ae,
                },
                RecipientOwner::Synthetic {
                    native: b,
                    current: bc,
                    expires: be,
                },
            ) => {
                if a != b || !std::sync::Arc::ptr_eq(ac, bc) || ae != be {
                    return Err(Error::Authentication);
                }
                Ok(())
            }
            #[cfg(all(test, feature = "synthetic-qualification"))]
            _ => Err(Error::Authentication),
        }
    }
    pub(super) fn display(&self) -> String {
        format!(
            "\nAuthenticated evidence recipient: {}\nGrant: {}\nProcess PID {} / UID {} / instance {}\nChannel: {}\nGrant generation: {}\nExact recipient binding: {}\nDisclosure: source/destination association, exact address/network and ownership-review reference only. This information cannot be recalled after release. The paired application receives no viewing key, spending permission or current retirement-completion authority.",
            super::state::inert_text(&self.binding.application_label),
            self.binding.grant_id,
            self.binding.pid,
            self.binding.uid,
            self.binding.process_instance,
            self.binding.channel_digest,
            self.binding.generation,
            self.digest
        )
    }
}
fn binding_digest(binding: &RecipientBinding) -> Result<String> {
    binding.scope.validate().map_err(|_| Error::InvalidData)?;
    for digest in [
        &binding.grant_id,
        &binding.channel_digest,
        &binding.key_digest,
        &binding.process_instance,
        &binding.native_entry,
    ] {
        wholepact_core::proposal::validate_sha256(digest).map_err(|_| Error::InvalidData)?;
    }
    wholepact_core::proposal::canonical_digest(
        "wholepact:retirement-evidence-recipient:v1",
        binding,
    )
    .map_err(|_| Error::InvalidData)
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod tests;
