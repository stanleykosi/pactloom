//! Restriction-only attachment for one real, already-bound synthetic fixture
//! endpoint. This module cannot construct its nominal native fixture owner.
//! The owner is never selected by wire, environment, CLI, bool or global flag.
use super::*;
use crate::native_ui::{NativeAuthorityBinding, ScopedV3FixtureDispatch};
use std::sync::{MutexGuard, OnceLock};

/// All clones refer to the same immutable one-shot attachment. Keeping the
/// admission lock separate from the original grant registry permits a single
/// fail-fast linearization point without changing token authentication.
#[derive(Clone, Default)]
pub(super) struct ScopedBornQualificationV3 {
    owner: Arc<OnceLock<Arc<ScopedV3FixtureDispatch>>>,
    admission: Arc<Mutex<()>>,
}
impl ScopedBornQualificationV3 {
    /// The caller keeps this guard through its existing event enqueue or grant
    /// issuance. Reads occur beforehand; contention fails rather than waiting.
    pub(super) fn begin_admission(&self) -> Result<MutexGuard<'_, ()>> {
        self.admission.try_lock().map_err(|_| Error::Locked)
    }

    /// Pre-authentication pairing data is only rejected or forwarded to the
    /// original native review. It never creates a peer or consumes a phase.
    pub(super) fn require_pairing_scope(&self, scope: &PairScope) -> Result<()> {
        match self.owner.get() {
            Some(owner) => owner.require_scope(scope),
            None => Ok(()),
        }
    }

    /// Native approval must still produce the original decision. Recheck the
    /// exact scope and pointer-identical native owner immediately before issue.
    pub(super) fn require_pairing_owner(
        &self,
        scope: &PairScope,
        native: &NativeAuthorityBinding,
    ) -> Result<()> {
        if let Some(owner) = self.owner.get() {
            owner.require_scope(scope)?;
            owner.require_native(native)?;
        }
        Ok(())
    }

    pub(super) fn authenticate(
        &self,
        grants: &Mutex<BTreeMap<String, Grant>>,
        observed: PeerProcess,
        id: &str,
        token: &str,
        request: &AppRequest,
        mode: &IpcMode,
    ) -> Result<AuthenticatedPeer> {
        let Some(owner) = self.owner.get() else {
            // No owner: the original ordinary/restricted validator, grant
            // authentication and global product refusal remain unchanged.
            return super::authenticate(grants, observed, id, token, request, mode);
        };
        if !matches!(mode, IpcMode::Ordinary) {
            return Err(Error::Authentication);
        }
        // No scope exception, field acceptance or phase consumption precedes
        // real kernel/PID/token/native/current/original-expiry authentication.
        let peer = authenticate_grant(grants, observed, id, token)?;
        owner.require_native(&peer.native_origin)?;
        owner.require_scope(&peer.scope)?;
        match request {
            AppRequest::Status {} => request.validate(&peer.scope)?,
            _ => common_context_scope_v3::validate_fields(request, &peer.scope)?,
        }
        // Only an exact predetermined request family and original can consume
        // the next phase. A later delivery failure does not restore that phase.
        owner.admit_authenticated(request, &peer.scope)?;
        peer.check_current()?;
        Ok(peer)
    }
}

impl LocalIpc {
    /// Used only by the finite retained-account fixture after authenticating its
    /// actual controller. There is no constructor here and no replacement API.
    /// The existing socket and grants are retained, never rebound or renewed.
    pub(crate) fn attach_scoped_born_qualification_v3(
        &mut self,
        owner: Arc<ScopedV3FixtureDispatch>,
    ) -> Result<()> {
        let _admission = self.scoped_born_qualification_v3.begin_admission()?;
        if !matches!(self.mode, IpcMode::Ordinary)
            || self.stop.load(Ordering::Acquire)
            || self.admission_closed.load(Ordering::Acquire)
            || self.scoped_born_qualification_v3.owner.get().is_some()
        {
            return Err(Error::Locked);
        }
        owner.require_endpoint(&self.path)?;
        // The native fixture also requires no in-progress job or review. Fail
        // this attachment if a previously admitted event is still queued; drop
        // all such events rather than reinterpret them as scoped qualification.
        let mut had_queued_event = false;
        while self.events.try_recv().is_ok() {
            had_queued_event = true;
        }
        if had_queued_event {
            return Err(Error::ReviewMismatch);
        }
        owner.require_endpoint(&self.path)?;
        self.scoped_born_qualification_v3
            .owner
            .set(owner)
            .map_err(|_| Error::Locked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_fail_fast_admission_lock_without_creating_owner() {
        let holder = ScopedBornQualificationV3::default();
        let clone = holder.clone();
        assert!(Arc::ptr_eq(&holder.owner, &clone.owner));
        let held = holder.begin_admission().unwrap();
        assert!(matches!(clone.begin_admission(), Err(Error::Locked)));
        assert!(holder.owner.get().is_none());
        drop(held);
        assert!(clone.begin_admission().is_ok());
        assert!(clone.owner.get().is_none());
    }
}
