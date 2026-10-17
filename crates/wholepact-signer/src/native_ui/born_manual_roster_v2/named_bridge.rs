//! Actual consumed-born lane adapter to the existing purpose-specific native
//! history and dispatch issuers. No caller DTO can construct a live owner.
use super::named_continuation::ConsumedBornNamedOwnerV1;
use crate::{
    Error, Result,
    authority_bridge::{
        born_dispatch_ipc::BornDispatchRequestV1, born_history_ipc::BornOriginalHistoryRequestV1,
    },
    consent_journal::{LiveNamedRecipientProfile, SignerConsentJournal, SignerConsentSession},
    ipc::{AuthenticatedPeer, LocalEvent},
    native_ui::{
        AuthenticatedPairing, NativeDecision, PendingAccountNativeAuthority,
        born_dispatch::{ApprovedBornDispatchV1, PreparedBornDispatchV1},
        born_history::{ApprovedBornHistoryV1, PreparedBornHistoryV1},
        witness_workspace::NativeWitnessWorkspace,
    },
};
use std::{
    os::unix::net::UnixStream,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    History,
    Dispatch,
}
enum Request {
    History(Box<BornOriginalHistoryRequestV1>),
    Dispatch(Box<BornDispatchRequestV1>),
}
impl Request {
    fn kind(&self) -> Kind {
        match self {
            Self::History(_) => Kind::History,
            Self::Dispatch(_) => Kind::Dispatch,
        }
    }
    fn original(&self) -> BornOriginalHistoryRequestV1 {
        match self {
            Self::History(r) => (**r).clone(),
            Self::Dispatch(r) => r.history(),
        }
    }
}

pub(super) struct Input {
    request: Request,
    profile: LiveNamedRecipientProfile,
    peer: AuthenticatedPeer,
    stream: UnixStream,
    owner: Arc<PendingAccountNativeAuthority>,
    cancelled: Arc<AtomicBool>,
}
enum Preparation {
    History(Box<PreparedBornHistoryV1>),
    Dispatch(Box<PreparedBornDispatchV1>),
}
pub(super) struct Prepared {
    preparation: Preparation,
    kind: Kind,
    original: BornOriginalHistoryRequestV1,
    owner: Arc<PendingAccountNativeAuthority>,
    cancelled: Arc<AtomicBool>,
}
enum Approval {
    History(Box<ApprovedBornHistoryV1>),
    Dispatch(Box<ApprovedBornDispatchV1>),
}
pub(super) struct Approved {
    approval: Approval,
    kind: Kind,
    original: BornOriginalHistoryRequestV1,
    owner: Arc<PendingAccountNativeAuthority>,
    cancelled: Arc<AtomicBool>,
    journal: Arc<SignerConsentJournal>,
    session: Arc<SignerConsentSession>,
    witness: Arc<NativeWitnessWorkspace>,
}
struct Worker {
    kind: Kind,
    original: BornOriginalHistoryRequestV1,
    cancelled: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

/// At most one historical and one dispatch channel for the SAME original.
/// Historical evidence holds no GUI job or exclusive journal guard while the
/// separate native dispatch decision is made. All unrelated writes stay denied.
#[derive(Default)]
pub(super) struct State {
    pending: Option<Arc<AtomicBool>>,
    workers: Vec<Worker>,
}
impl State {
    pub(super) fn held(&self) -> bool {
        !self.workers.is_empty()
    }
    pub(super) fn poll(&mut self) {
        self.workers.retain(|worker| !worker.thread.is_finished());
    }
    pub(super) fn queue(
        &mut self,
        event: LocalEvent,
        profile: LiveNamedRecipientProfile,
        owner: Arc<PendingAccountNativeAuthority>,
        expected_grant: &str,
    ) -> Result<Input> {
        self.poll();
        if self.pending.is_some() {
            return Err(Error::Locked);
        }
        owner.check_current()?;
        let (peer, stream, request) = match event {
            LocalEvent::BornOriginalHistoryV1 {
                peer,
                stream,
                request,
            } => {
                request.validate().map_err(|_| Error::ReviewMismatch)?;
                (peer, stream, Request::History(request))
            }
            LocalEvent::BornDispatchV1 {
                peer,
                stream,
                request,
            } => {
                request.validate().map_err(|_| Error::ReviewMismatch)?;
                (peer, stream, Request::Dispatch(request))
            }
            _ => return Err(Error::Unavailable),
        };
        peer.check_current()?;
        if peer.grant_id != expected_grant || peer.native_origin != owner.native().binding() {
            return Err(Error::ReviewMismatch);
        }
        let original = request.original();
        if !permits_join(
            self.workers
                .iter()
                .map(|worker| (worker.kind, &worker.original)),
            request.kind(),
            &original,
        ) {
            return Err(Error::Locked);
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        self.pending = Some(cancelled.clone());
        Ok(Input {
            request,
            profile,
            peer,
            stream,
            owner,
            cancelled,
        })
    }
    pub(super) fn adopt(
        &mut self,
        approved: Approved,
        owner: &PendingAccountNativeAuthority,
    ) -> Result<()> {
        owner.check_current()?;
        approved.owner.check_current()?;
        if self
            .pending
            .as_ref()
            .is_none_or(|pending| !Arc::ptr_eq(pending, &approved.cancelled))
            || approved.owner.native().binding() != owner.native().binding()
            || approved.cancelled.load(Ordering::Acquire)
        {
            approved.cancelled.store(true, Ordering::Release);
            return Err(Error::ReviewMismatch);
        }
        // The actual GUI adopts this result before any server worker starts.
        // A late completed preparation can therefore never create an untracked
        // held channel after blur/Lock has consumed the foreground owner.
        let worker = approved.start()?;
        self.pending = None;
        self.workers.push(worker);
        Ok(())
    }
    pub(super) fn cancel_and_drain(&mut self) -> Vec<JoinHandle<()>> {
        if let Some(pending) = self.pending.take() {
            pending.store(true, Ordering::Release);
        }
        self.workers
            .drain(..)
            .map(|worker| {
                worker.cancelled.store(true, Ordering::Release);
                worker.thread
            })
            .collect()
    }
}
impl Drop for State {
    fn drop(&mut self) {
        if let Some(pending) = &self.pending {
            pending.store(true, Ordering::Release);
        }
        for worker in &self.workers {
            worker.cancelled.store(true, Ordering::Release);
        }
    }
}
fn permits_join<'a>(
    mut held: impl Iterator<Item = (Kind, &'a BornOriginalHistoryRequestV1)>,
    kind: Kind,
    original: &BornOriginalHistoryRequestV1,
) -> bool {
    held.all(|(other_kind, other_original)| other_kind != kind && other_original == original)
}
impl Input {
    pub(super) fn prepare(self, actual: &ConsumedBornNamedOwnerV1) -> Result<Prepared> {
        actual.check(&self.owner)?;
        let pairing = AuthenticatedPairing::from_authenticated_request(self.peer.clone())?;
        actual.source().check_pairing(&pairing, &self.owner)?;
        let kind = self.request.kind();
        let original = self.request.original();
        let source = self.owner.native().binding();
        let preparation = match self.request {
            Request::History(request) => {
                Preparation::History(Box::new(PreparedBornHistoryV1::prepare(
                    *request,
                    self.profile,
                    self.peer,
                    self.stream,
                    actual.source().journal(),
                    actual.session()?,
                    &source,
                    actual.witness(),
                    self.cancelled.clone(),
                )?))
            }
            Request::Dispatch(request) => {
                Preparation::Dispatch(Box::new(PreparedBornDispatchV1::prepare(
                    *request,
                    self.profile,
                    self.peer,
                    self.stream,
                    actual.source().journal(),
                    actual.session()?,
                    &source,
                    actual.witness(),
                    self.cancelled.clone(),
                )?))
            }
        };
        actual.check(&self.owner)?;
        Ok(Prepared {
            preparation,
            kind,
            original,
            owner: self.owner,
            cancelled: self.cancelled,
        })
    }
}
impl Prepared {
    pub(super) fn display(&self) -> Result<(String, String)> {
        self.owner.check_current()?;
        if self.cancelled.load(Ordering::Acquire) {
            return Err(Error::Locked);
        }
        match &self.preparation {
            Preparation::History(p) => Ok((p.digest().into(), p.display()?)),
            Preparation::Dispatch(p) => Ok((p.digest().into(), p.display()?)),
        }
    }
    pub(super) fn approve(
        self,
        decision: NativeDecision,
        actual: &ConsumedBornNamedOwnerV1,
        current_owner: &PendingAccountNativeAuthority,
    ) -> Result<Approved> {
        actual.check(current_owner)?;
        self.owner.check_current()?;
        if self.owner.native().binding() != current_owner.native().binding()
            || self.cancelled.load(Ordering::Acquire)
        {
            return Err(Error::Locked);
        }
        let journal = actual.source().journal().clone();
        let session = actual.session()?.clone();
        let witness = actual.witness().clone();
        let approval = match self.preparation {
            Preparation::History(p) => {
                Approval::History(Box::new(p.approve(decision, self.owner.native())?))
            }
            Preparation::Dispatch(p) => {
                Approval::Dispatch(Box::new(p.approve(decision, self.owner.native())?))
            }
        };
        Ok(Approved {
            approval,
            kind: self.kind,
            original: self.original,
            owner: self.owner,
            cancelled: self.cancelled,
            journal,
            session,
            witness,
        })
    }
}
impl Approved {
    fn start(self) -> Result<Worker> {
        self.owner.check_current()?;
        if self.cancelled.load(Ordering::Acquire) {
            return Err(Error::Locked);
        }
        let Self {
            approval,
            kind,
            original,
            owner,
            cancelled,
            journal,
            session,
            witness,
        } = self;
        let thread = match approval {
            Approval::History(approved) => {
                std::thread::Builder::new()
                    .name("wholepact-born-named-history".into())
                    .spawn(move || {
                        // Retain genuine native owner through conservative channel drain;
                        // GUI revocation remains immediate and closes new admission.
                        let _owner = owner;
                        let _ = approved.serve(&journal, &session, &witness);
                    })?
            }
            Approval::Dispatch(approved) => std::thread::Builder::new()
                .name("wholepact-born-named-dispatch".into())
                .spawn(move || {
                    let _owner = owner;
                    let _ = approved.serve(&journal, &session, &witness);
                })?,
        };
        Ok(Worker {
            kind,
            original,
            cancelled,
            thread,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn original(label: &str) -> BornOriginalHistoryRequestV1 {
        BornOriginalHistoryRequestV1 {
            authorization_id: label.into(),
            expected_original_ref: "11".repeat(32),
            expected_born_origin_digest: "22".repeat(32),
        }
    }
    #[test]
    fn held_history_allows_only_distinct_dispatch_for_same_original() {
        let a = original("original-a");
        let b = original("original-b");
        assert!(permits_join(std::iter::empty(), Kind::History, &a));
        assert!(permits_join(
            [(Kind::History, &a)].into_iter(),
            Kind::Dispatch,
            &a
        ));
        assert!(!permits_join(
            [(Kind::History, &a)].into_iter(),
            Kind::History,
            &a
        ));
        assert!(!permits_join(
            [(Kind::History, &a)].into_iter(),
            Kind::Dispatch,
            &b
        ));
        assert!(!permits_join(
            [(Kind::Dispatch, &a)].into_iter(),
            Kind::Dispatch,
            &a
        ));
    }
    #[test]
    fn clearing_pending_admission_revokes_before_any_drain() {
        let token = Arc::new(AtomicBool::new(false));
        let mut state = State {
            pending: Some(token.clone()),
            workers: vec![],
        };
        assert!(state.cancel_and_drain().is_empty());
        assert!(token.load(Ordering::Acquire));
        assert!(state.pending.is_none());
    }
}

#[cfg(feature = "synthetic-born-joined-qualification")]
impl Prepared {
    pub(in crate::native_ui) fn synthetic_for_authorization(&self, authorization: &str) -> bool {
        self.original.authorization_id == authorization
    }
}
