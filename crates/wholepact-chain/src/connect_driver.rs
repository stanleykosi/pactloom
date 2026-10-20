//! Independently polled public connection establishment, never an RPC dispatcher.
//! The original caller supplies its absolute deadline. No wallet, permission,
//! request body, or credential enrollment crosses this task boundary.
use crate::{ChainError, proxy::ProxyRoute};
use tokio::{task::JoinHandle, time::Instant};
use tonic::transport::{Channel, Endpoint};

#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestConnectObservation {
    pub(crate) started: std::sync::atomic::AtomicBool,
    pub(crate) finished: std::sync::atomic::AtomicBool,
    pub(crate) succeeded: std::sync::atomic::AtomicBool,
}
#[cfg(test)]
struct TestTaskExit(Option<std::sync::Arc<TestConnectObservation>>);
#[cfg(test)]
impl Drop for TestTaskExit {
    fn drop(&mut self) {
        if let Some(observation) = &self.0 {
            observation.finished.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

struct OwnedConnect(JoinHandle<Result<Channel, ChainError>>);
impl Drop for OwnedConnect {
    fn drop(&mut self) {
        // External future cancellation cannot await in Drop. Abort is requested
        // here; the runtime must resume to destroy the task and its socket/output.
        // A completed, unclaimed Channel is dropped with the JoinHandle output.
        self.0.abort();
    }
}

pub(crate) async fn connect_until(
    route: ProxyRoute,
    endpoint: Endpoint,
    deadline: Instant,
) -> Result<Channel, ChainError> {
    connect_until_inner(route, endpoint, deadline, #[cfg(test)] None).await
}

#[cfg(test)]
pub(crate) async fn connect_until_observed(
    route: ProxyRoute,
    endpoint: Endpoint,
    deadline: Instant,
    observation: std::sync::Arc<TestConnectObservation>,
) -> Result<Channel, ChainError> {
    connect_until_inner(route, endpoint, deadline, Some(observation)).await
}

async fn connect_until_inner(
    route: ProxyRoute,
    endpoint: Endpoint,
    deadline: Instant,
    #[cfg(test)] observation: Option<std::sync::Arc<TestConnectObservation>>,
) -> Result<Channel, ChainError> {
    if Instant::now() >= deadline {
        return Err(ChainError::Timeout);
    }
    // Captured before spawn so an abort before the first task poll is observable.
    #[cfg(test)]
    let test_exit = TestTaskExit(observation.clone());
    let mut owned = OwnedConnect(tokio::spawn(async move {
        #[cfg(test)]
        let _test_exit = test_exit;
        #[cfg(test)]
        if let Some(observation) = &observation {
            observation.started.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        // Recheck before polling the connector: scheduling delay cannot grant
        // a new interval or permit an expired task to start a connection.
        if Instant::now() >= deadline {
            return Err(ChainError::Timeout);
        }
        let result = tokio::time::timeout_at(deadline, route.connect(&endpoint))
            .await
            .unwrap_or(Err(ChainError::Timeout));
        #[cfg(test)]
        if let Some(observation) = &observation {
            observation.succeeded.store(result.is_ok(), std::sync::atomic::Ordering::SeqCst);
        }
        result
    }));
    let result = tokio::select! {
        biased;
        _ = tokio::time::sleep_until(deadline) => {
            owned.0.abort();
            // Explicit timeout drains our connect task. Tonic's internal channel
            // workers retain their existing drop-driven shutdown semantics.
            let _ = (&mut owned.0).await;
            return Err(ChainError::Timeout);
        }
        result = &mut owned.0 => result.map_err(|_| ChainError::TransportUnavailable)?,
    };
    // The owner can be synchronously occupied after the worker completes. Never
    // let its queued successful Channel escape the original observation budget.
    if Instant::now() >= deadline {
        drop(result);
        return Err(ChainError::Timeout);
    }
    result
}
