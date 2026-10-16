//! Native-reviewed read-only metadata. Only a live pinned signer response can
//! construct this opaque result. Serialized snapshots confer no authority.
use super::{BridgeError, Result, dispatch_ipc::write_frame, ipc::OriginalHistoryClient};
use serde::{Deserialize, Serialize};
use std::{
    os::unix::net::UnixStream,
    sync::Mutex,
    time::{Duration, Instant},
};
pub use wholepact_core::owner_inspection::{OwnerInspectionRequest, OwnerInspectionSnapshot};
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum InspectionResponse {
    Reviewed {
        snapshot: Box<OwnerInspectionSnapshot>,
    },
    Current,
    Finished,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum InspectionCommand {
    CheckCurrent,
    Finish,
}

pub struct NativeOwnerInspection<'a> {
    client: &'a OriginalHistoryClient,
    stream: Mutex<UnixStream>,
    snapshot: OwnerInspectionSnapshot,
    started: Instant,
}
impl OriginalHistoryClient {
    pub fn request_owner_inspection(
        &self,
        request: &OwnerInspectionRequest,
    ) -> Result<NativeOwnerInspection<'_>> {
        if !request.validate() {
            return Err(BridgeError::Binding);
        }
        let stream = self.open_inspection_request(
            serde_json::json!({"operation":"request_owner_inspection", "request":request}),
        )?;
        let bytes =
            crate::ipc::read_frame_with_deadline(&stream, self.peer(), Duration::from_secs(120))
                .map_err(|_| BridgeError::Ipc)?;
        let InspectionResponse::Reviewed { snapshot } =
            serde_json::from_slice(&bytes).map_err(|_| BridgeError::Ipc)?
        else {
            return Err(BridgeError::Permission);
        };
        if snapshot.request != *request || !snapshot.validate() {
            return Err(BridgeError::Binding);
        }
        let result = NativeOwnerInspection {
            client: self,
            stream: Mutex::new(stream),
            snapshot: *snapshot,
            started: Instant::now(),
        };
        result.check_current()?;
        Ok(result)
    }
}
impl NativeOwnerInspection<'_> {
    pub fn snapshot(&self) -> &OwnerInspectionSnapshot {
        &self.snapshot
    }
    pub fn check_current(&self) -> Result<()> {
        if self.started.elapsed() >= Duration::from_secs(120) {
            return Err(BridgeError::Permission);
        }
        self.client
            .peer()
            .check_alive()
            .map_err(|_| BridgeError::Permission)?;
        let mut stream = self.stream.lock().map_err(|_| BridgeError::Ipc)?;
        write_frame(&mut stream, &InspectionCommand::CheckCurrent)?;
        let bytes = crate::ipc::read_frame_with_deadline(
            &stream,
            self.client.peer(),
            Duration::from_secs(2),
        )
        .map_err(|_| BridgeError::Ipc)?;
        match serde_json::from_slice(&bytes).map_err(|_| BridgeError::Ipc)? {
            InspectionResponse::Current => Ok(()),
            _ => Err(BridgeError::Permission),
        }
    }
}
impl Drop for NativeOwnerInspection<'_> {
    fn drop(&mut self) {
        if let Ok(mut stream) = self.stream.lock() {
            let _ = write_frame(&mut stream, &InspectionCommand::Finish);
        }
    }
}
