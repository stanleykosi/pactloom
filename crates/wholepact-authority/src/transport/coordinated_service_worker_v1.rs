//! Private ownership of one actual fixed-role service worker and its inherited
//! control edge. Failure is observable before a possibly blocking owned join.
//! No hard cleanup bound is claimed; the original parent still owns process
//! termination/reap if a worker cannot return. No unfinished handle is detached.
use crate::{AuthorityError, Result};
use std::sync::{atomic::{AtomicBool, Ordering}, mpsc::{self, Receiver, SyncSender}, Arc};
use std::thread::JoinHandle;

pub(super) trait ServiceOriginV1 {
    fn close_failed_worker(&mut self);
    fn close_failed_worker_error(&mut self);
    fn complete_owned(self, result: Result<()>) -> !;
}
#[cfg(feature = "coordinated-witness-financial-history")]
impl ServiceOriginV1 for wholepact_financial_coordinator_origin::WitnessFinancialHistoryOriginV1 {
    fn close_failed_worker(&mut self) { self.close_for_failed_worker_v1(); }
    fn close_failed_worker_error(&mut self) { self.close_for_failed_worker_error_v1(); }
    fn complete_owned(self, result: Result<()>) -> ! {
        self.complete(result.map_err(|_| std::io::Error::other("initial owner-history role stopped")))
    }
}
#[cfg(feature = "coordinated-witness-financial-signing")]
impl ServiceOriginV1 for wholepact_financial_coordinator_origin::WitnessFinancialSigningOriginV1 {
    fn close_failed_worker(&mut self) { self.close_for_failed_worker_v1(); }
    fn close_failed_worker_error(&mut self) { self.close_for_failed_worker_error_v1(); }
    fn complete_owned(self, result: Result<()>) -> ! {
        self.complete(result.map_err(|_| std::io::Error::other("original financial-signing role stopped")))
    }
}
pub(super) struct ServiceWorkerOwnerV1<O: ServiceOriginV1, G, E> {
    pub(super) origin: Option<O>,
    pub(super) stopped: Arc<AtomicBool>,
    pub(super) worker: Option<JoinHandle<Result<()>>>,
    pub(super) serve_tx: Option<SyncSender<G>>,
    pub(super) event_tx: SyncSender<E>,
    pub(super) event_rx: Receiver<E>,
}
impl<O: ServiceOriginV1, G, E> ServiceWorkerOwnerV1<O, G, E> {
    pub(super) fn new(origin: O) -> Self {
        let (event_tx, event_rx) = mpsc::sync_channel(2);
        Self { origin: Some(origin), stopped: Arc::new(AtomicBool::new(false)),
            worker: None, serve_tx: None, event_tx, event_rx }
    }
    fn close_and_join(&mut self, actual_work_error: bool) -> Result<()> {
        // Publish restriction and close the actual edge BEFORE dropping a queued
        // grant or waiting on a worker. The parent can observe failure meanwhile.
        self.stopped.store(true, Ordering::Release);
        if let Some(origin) = self.origin.as_mut() {
            if actual_work_error { origin.close_failed_worker_error(); }
            else { origin.close_failed_worker(); }
        }
        drop(self.serve_tx.take());
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| AuthorityError::Storage)??;
        }
        Ok(())
    }
    pub(super) fn complete(mut self, mut result: Result<()>) -> ! {
        // A successful monitor must already have joined the worker and completed
        // its genuine disposal protocol. Never promote an outstanding join.
        if result.is_ok() && self.worker.is_some() { result = Err(AuthorityError::Permission); }
        if result.is_err() {
            // Preserve the original work error; cleanup cannot turn it into success.
            let _ = self.close_and_join(true);
        }
        let origin = self.origin.take().expect("owned service origin retained until completion");
        drop(self);
        origin.complete_owned(result)
    }
}
impl<O: ServiceOriginV1, G, E> Drop for ServiceWorkerOwnerV1<O, G, E> {
    fn drop(&mut self) {
        if self.origin.is_some() || self.worker.is_some() { let _ = self.close_and_join(false); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    struct FakeOrigin { events: Arc<Mutex<Vec<&'static str>>>, stop: Option<Arc<AtomicBool>> }
    impl ServiceOriginV1 for FakeOrigin {
        fn close_failed_worker(&mut self) {
            assert!(self.stop.as_ref().unwrap().load(Ordering::Acquire));
            self.events.lock().unwrap().push("edge_closed");
        }
        fn close_failed_worker_error(&mut self) {
            assert!(self.stop.as_ref().unwrap().load(Ordering::Acquire));
            self.events.lock().unwrap().push("failure_observed");
            self.close_failed_worker();
        }
        fn complete_owned(self, result: Result<()>) -> ! {
            self.events.lock().unwrap().push("completed");
            std::panic::panic_any(Completed(result))
        }
    }
    impl Drop for FakeOrigin { fn drop(&mut self) { self.events.lock().unwrap().push("origin_dropped"); } }
    #[derive(Debug)]
    struct Completed(Result<()>);
    struct Event(Arc<Mutex<Vec<&'static str>>>);
    impl Drop for Event { fn drop(&mut self) { self.0.lock().unwrap().push("queue_dropped"); } }
    fn prepared(events: Arc<Mutex<Vec<&'static str>>>) -> ServiceWorkerOwnerV1<FakeOrigin, (), Event> {
        let mut owner = ServiceWorkerOwnerV1::new(FakeOrigin { events: events.clone(), stop: None });
        owner.origin.as_mut().unwrap().stop = Some(owner.stopped.clone());
        assert!(owner.event_tx.try_send(Event(events)).is_ok());
        owner
    }
    #[test]
    fn service_owner_restricts_and_closes_edge_before_owned_queue_drop() {
        let events = Arc::new(Mutex::new(Vec::new()));
        drop(prepared(events.clone()));
        assert_eq!(*events.lock().unwrap(), ["edge_closed", "origin_dropped", "queue_dropped"]);
    }
    #[test]
    fn service_owner_unwind_keeps_same_failure_cleanup_order() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = events.clone();
        assert!(std::panic::catch_unwind(move || {
            let _owner = prepared(captured);
            panic!("synthetic monitor unwind");
        }).is_err());
        assert_eq!(*events.lock().unwrap(), ["edge_closed", "origin_dropped", "queue_dropped"]);
    }

    #[test]
    fn actual_monitor_error_observes_before_edge_queue_and_join_and_keeps_original_error() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut owner = prepared(events.clone());
        let (tx, rx) = mpsc::sync_channel(1);
        owner.serve_tx = Some(tx);
        let worker_events = events.clone();
        owner.worker = Some(std::thread::spawn(move || {
            assert!(rx.recv().is_err());
            worker_events.lock().unwrap().push("worker_finished");
            Err(AuthorityError::Storage)
        }));
        let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.complete(Err(AuthorityError::Conflict))
        })).unwrap_err();
        assert_eq!(ended.downcast_ref::<Completed>().unwrap().0, Err(AuthorityError::Conflict));
        assert_eq!(*events.lock().unwrap(), ["failure_observed", "edge_closed", "worker_finished", "queue_dropped", "completed", "origin_dropped"]);
    }
    #[test]
    fn actual_success_does_not_observe_failure_or_close_an_edge() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let owner = prepared(events.clone());
        let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.complete(Ok(())))).unwrap_err();
        assert_eq!(ended.downcast_ref::<Completed>().unwrap().0, Ok(()));
        assert_eq!(*events.lock().unwrap(), ["queue_dropped", "completed", "origin_dropped"]);
    }
    #[test]
    fn outstanding_worker_still_prevents_success_and_uses_actual_error_path() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut owner = prepared(events.clone());
        owner.worker = Some(std::thread::spawn(|| Ok(())));
        let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.complete(Ok(())))).unwrap_err();
        assert_eq!(ended.downcast_ref::<Completed>().unwrap().0, Err(AuthorityError::Permission));
        assert_eq!(*events.lock().unwrap(), ["failure_observed", "edge_closed", "queue_dropped", "completed", "origin_dropped"]);
    }
}
