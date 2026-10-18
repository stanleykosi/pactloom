//! Synthetic, data-only observations of the existing checked-history kernel.
//! A stage or I/O class is not permission or proof of native deadline expiry.
use crate::{AuthorityError, Result};
use std::{
    cell::Cell,
    io::{self, Read, Write},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CheckedHistoryStageV1 {
    CallerDeadline,
    ExchangeDeadline,
    SourceCallback,
    SnapshotConnect,
    SnapshotHandshake,
    SnapshotPeerBinding,
    SnapshotRequestBuild,
    SnapshotRequestWrite,
    SnapshotResponseRead,
    SnapshotResponse,
    SnapshotValidation,
    PageConnect,
    PageHandshake,
    PagePeerBinding,
    PageRequestBuild,
    PageRequestWrite,
    PageResponseRead,
    PageResponse,
    PageValidation,
    EventReplay,
    FinalValidation,
    Bounds,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CheckedHistoryIoKindV1 {
    Timeout,
    Closed,
    Refused,
    Other,
}

/// Owns the first original authority error, with no payload or transport detail.
/// No public constructor, serialization, cloning, Debug or Display is exposed.
pub struct CheckedHistoryFailureV1 {
    stage: CheckedHistoryStageV1,
    io_kind: Option<CheckedHistoryIoKindV1>,
    error: AuthorityError,
}
impl CheckedHistoryFailureV1 {
    pub fn stage(&self) -> CheckedHistoryStageV1 {
        self.stage
    }
    pub fn io_kind(&self) -> Option<CheckedHistoryIoKindV1> {
        self.io_kind
    }
    /// The first original observed error, before any existing outer blanket
    /// mapping. Ordinary callers still receive their unchanged mapped error.
    pub fn into_error(self) -> AuthorityError {
        self.error
    }
}

pub(super) struct HistoryObserverV1 {
    stage: Cell<CheckedHistoryStageV1>,
    io_kind: Cell<Option<CheckedHistoryIoKindV1>>,
    first: Cell<Option<CheckedHistoryFailureV1>>,
}
impl HistoryObserverV1 {
    pub(super) fn new() -> Self {
        Self {
            stage: Cell::new(CheckedHistoryStageV1::CallerDeadline),
            io_kind: Cell::new(None),
            first: Cell::new(None),
        }
    }
    pub(super) fn enter(&self, stage: CheckedHistoryStageV1) {
        self.stage.set(stage);
        self.io_kind.set(None);
    }
    pub(super) fn record(
        &self,
        stage: CheckedHistoryStageV1,
        io_kind: Option<CheckedHistoryIoKindV1>,
        error: AuthorityError,
    ) {
        // Taking and replacing keeps the first owned error without requiring
        // the public diagnostic container to implement Clone or Copy.
        self.first
            .set(Some(self.first.take().unwrap_or(CheckedHistoryFailureV1 {
                stage,
                io_kind,
                error,
            })));
    }
    pub(super) fn observe_io<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if let Err(error) = &result {
            if self.io_kind.get().is_none() {
                self.io_kind.set(Some(classify_io(error.kind())));
            }
        }
        result
    }
    fn observe_authority<T>(&self, result: Result<T>) -> Result<T> {
        if let Err(error) = &result {
            self.record(self.stage.get(), self.io_kind.get(), *error);
        }
        result
    }
    pub(super) fn into_failure(self, error: AuthorityError) -> CheckedHistoryFailureV1 {
        self.first.into_inner().unwrap_or(CheckedHistoryFailureV1 {
            stage: self.stage.get(),
            io_kind: self.io_kind.get(),
            error,
        })
    }
}

fn classify_io(kind: io::ErrorKind) -> CheckedHistoryIoKindV1 {
    match kind {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => CheckedHistoryIoKindV1::Timeout,
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotConnected => CheckedHistoryIoKindV1::Closed,
        io::ErrorKind::ConnectionRefused => CheckedHistoryIoKindV1::Refused,
        _ => CheckedHistoryIoKindV1::Other,
    }
}

/// Classify only the bound already selected by the unchanged kernel. Neither
/// this label nor an I/O timeout establishes native permission expiry.
pub(super) fn selected_deadline_stage(
    selected: std::time::Instant,
    caller: Option<std::time::Instant>,
) -> CheckedHistoryStageV1 {
    if caller.is_some_and(|caller| selected < caller) {
        CheckedHistoryStageV1::ExchangeDeadline
    } else {
        CheckedHistoryStageV1::CallerDeadline
    }
}

#[derive(Clone, Copy)]
pub(super) enum HistoryPhaseV1 {
    Snapshot,
    Page,
}
#[derive(Clone, Copy)]
pub(super) enum HistoryCallStepV1 {
    Connect,
    Handshake,
    PeerBinding,
    RequestBuild,
    RequestWrite,
    ResponseRead,
    Response,
}
impl HistoryPhaseV1 {
    pub(super) fn stage(self, step: HistoryCallStepV1) -> CheckedHistoryStageV1 {
        use CheckedHistoryStageV1 as S;
        use HistoryCallStepV1 as C;
        match (self, step) {
            (Self::Snapshot, C::Connect) => S::SnapshotConnect,
            (Self::Snapshot, C::Handshake) => S::SnapshotHandshake,
            (Self::Snapshot, C::PeerBinding) => S::SnapshotPeerBinding,
            (Self::Snapshot, C::RequestBuild) => S::SnapshotRequestBuild,
            (Self::Snapshot, C::RequestWrite) => S::SnapshotRequestWrite,
            (Self::Snapshot, C::ResponseRead) => S::SnapshotResponseRead,
            (Self::Snapshot, C::Response) => S::SnapshotResponse,
            (Self::Page, C::Connect) => S::PageConnect,
            (Self::Page, C::Handshake) => S::PageHandshake,
            (Self::Page, C::PeerBinding) => S::PagePeerBinding,
            (Self::Page, C::RequestBuild) => S::PageRequestBuild,
            (Self::Page, C::RequestWrite) => S::PageRequestWrite,
            (Self::Page, C::ResponseRead) => S::PageResponseRead,
            (Self::Page, C::Response) => S::PageResponse,
        }
    }
}

/// Borrows the SAME maintained stream. Override the complete operations used
/// by framing so its specialized methods, retry behavior and flush run once.
/// The wrapper owns no stream, buffer, drop behavior, deadline or permission.
struct ObservedFrameIoV1<'a, S> {
    inner: &'a mut S,
    observer: &'a HistoryObserverV1,
}
impl<S: Read> Read for ObservedFrameIoV1<'_, S> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.observer.observe_io(self.inner.read(bytes))
    }
    fn read_exact(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        self.observer.observe_io(self.inner.read_exact(bytes))
    }
}
impl<S: Write> Write for ObservedFrameIoV1<'_, S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.observer.observe_io(self.inner.write(bytes))
    }
    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.observer.observe_io(self.inner.write_all(bytes))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.observer.observe_io(self.inner.flush())
    }
}
pub(super) fn read_frame_observed<T: serde::de::DeserializeOwned>(
    stream: &mut impl Read,
    observer: Option<&HistoryObserverV1>,
) -> Result<T> {
    match observer {
        Some(observer) => observer.observe_authority(super::read_frame(&mut ObservedFrameIoV1 {
            inner: stream,
            observer,
        })),
        None => super::read_frame(stream),
    }
}
pub(super) fn write_frame_observed<T: serde::Serialize>(
    stream: &mut impl Write,
    message: &T,
    observer: Option<&HistoryObserverV1>,
) -> Result<()> {
    match observer {
        Some(observer) => observer.observe_authority(super::write_frame(
            &mut ObservedFrameIoV1 {
                inner: stream,
                observer,
            },
            message,
        )),
        None => super::write_frame(stream, message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_deadline_label_uses_only_the_existing_bounds() {
        let selected = std::time::Instant::now();
        assert!(
            selected_deadline_stage(selected, Some(selected))
                == CheckedHistoryStageV1::CallerDeadline
        );
        assert!(
            selected_deadline_stage(selected, Some(selected + std::time::Duration::from_secs(1)))
                == CheckedHistoryStageV1::ExchangeDeadline
        );
        assert!(selected_deadline_stage(selected, None) == CheckedHistoryStageV1::CallerDeadline);
    }

    #[test]
    fn first_failure_retains_original_error_and_classification() {
        let observer = HistoryObserverV1::new();
        observer.record(
            CheckedHistoryStageV1::SourceCallback,
            None,
            AuthorityError::Permission,
        );
        observer.enter(CheckedHistoryStageV1::PageHandshake);
        observer.record(
            CheckedHistoryStageV1::PageHandshake,
            Some(CheckedHistoryIoKindV1::Timeout),
            AuthorityError::Authentication,
        );
        let failure = observer.into_failure(AuthorityError::Uncertain);
        assert!(failure.stage() == CheckedHistoryStageV1::SourceCallback);
        assert!(failure.io_kind().is_none());
        assert!(matches!(failure.into_error(), AuthorityError::Permission));
    }

    #[test]
    fn original_frame_error_survives_the_unchanged_outer_uncertain_mapping() {
        let observer = HistoryObserverV1::new();
        observer.enter(CheckedHistoryStageV1::PageResponseRead);
        // A zero-sized frame is rejected before a body read, exactly as before.
        let mut bytes: &[u8] = &[0, 0, 0, 0];
        let read: Result<u8> = read_frame_observed(&mut bytes, Some(&observer));
        let mapped = read.map_err(|_| AuthorityError::Uncertain);
        assert!(matches!(mapped, Err(AuthorityError::Uncertain)));
        let failure = observer.into_failure(mapped.err().unwrap());
        assert!(failure.stage() == CheckedHistoryStageV1::PageResponseRead);
        assert!(failure.io_kind().is_none());
        assert!(matches!(failure.into_error(), AuthorityError::Limit));

        let mut bytes: &[u8] = &[0, 0, 0, 0];
        let read: Result<u8> = read_frame_observed(&mut bytes, None);
        assert!(matches!(read, Err(AuthorityError::Limit)));
        assert!(matches!(
            read.map_err(|_| AuthorityError::Uncertain),
            Err(AuthorityError::Uncertain)
        ));
    }

    #[test]
    fn phases_and_io_kinds_have_only_finite_exact_mapping() {
        use CheckedHistoryStageV1 as S;
        use HistoryCallStepV1 as C;
        for (step, snapshot, page) in [
            (C::Connect, S::SnapshotConnect, S::PageConnect),
            (C::Handshake, S::SnapshotHandshake, S::PageHandshake),
            (C::PeerBinding, S::SnapshotPeerBinding, S::PagePeerBinding),
            (
                C::RequestBuild,
                S::SnapshotRequestBuild,
                S::PageRequestBuild,
            ),
            (
                C::RequestWrite,
                S::SnapshotRequestWrite,
                S::PageRequestWrite,
            ),
            (
                C::ResponseRead,
                S::SnapshotResponseRead,
                S::PageResponseRead,
            ),
            (C::Response, S::SnapshotResponse, S::PageResponse),
        ] {
            assert!(HistoryPhaseV1::Snapshot.stage(step) == snapshot);
            assert!(HistoryPhaseV1::Page.stage(step) == page);
        }
        use io::ErrorKind as E;
        use CheckedHistoryIoKindV1 as I;
        for (kind, expected) in [
            (E::TimedOut, I::Timeout),
            (E::WouldBlock, I::Timeout),
            (E::UnexpectedEof, I::Closed),
            (E::BrokenPipe, I::Closed),
            (E::ConnectionAborted, I::Closed),
            (E::ConnectionReset, I::Closed),
            (E::NotConnected, I::Closed),
            (E::ConnectionRefused, I::Refused),
            (E::InvalidData, I::Other),
            (E::Interrupted, I::Other),
        ] {
            assert!(classify_io(kind) == expected);
        }
    }

    #[derive(Default)]
    struct ExactOperations {
        reads: usize,
        writes: usize,
        flushes: usize,
        failure: Option<io::ErrorKind>,
    }
    impl Read for ExactOperations {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("must forward specialized read_exact, not replace its loop")
        }
        fn read_exact(&mut self, bytes: &mut [u8]) -> io::Result<()> {
            self.reads += 1;
            if let Some(kind) = self.failure {
                return Err(io::Error::from(kind));
            }
            if self.reads == 1 {
                bytes.copy_from_slice(&1_u32.to_be_bytes());
            } else {
                bytes.copy_from_slice(b"0");
            }
            Ok(())
        }
    }
    impl Write for ExactOperations {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("must forward specialized write_all, not replace its loop")
        }
        fn write_all(&mut self, _: &[u8]) -> io::Result<()> {
            self.writes += 1;
            if let Some(kind) = self.failure {
                return Err(io::Error::from(kind));
            }
            Ok(())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn frame_observer_and_none_forward_identical_complete_operations() {
        let observer = HistoryObserverV1::new();
        for optional in [None, Some(&observer)] {
            let mut stream = ExactOperations::default();
            write_frame_observed(&mut stream, &0, optional).unwrap();
            let value: u8 = read_frame_observed(&mut stream, optional).unwrap();
            assert_eq!(value, 0);
            assert_eq!((stream.reads, stream.writes, stream.flushes), (2, 2, 1));
        }
        assert!(observer.io_kind.get().is_none());
        assert!(observer.first.take().is_none());
    }

    #[test]
    fn frame_error_mapping_is_unchanged_with_or_without_observer() {
        let observer = HistoryObserverV1::new();
        observer.enter(CheckedHistoryStageV1::SnapshotResponseRead);
        for optional in [None, Some(&observer)] {
            let mut stream = ExactOperations {
                failure: Some(io::ErrorKind::TimedOut),
                ..Default::default()
            };
            let result: Result<u8> = read_frame_observed(&mut stream, optional);
            assert!(matches!(result, Err(AuthorityError::Uncertain)));
            assert_eq!(stream.reads, 1);
        }
        let failure = observer.into_failure(AuthorityError::Uncertain);
        assert!(failure.stage() == CheckedHistoryStageV1::SnapshotResponseRead);
        assert!(failure.io_kind() == Some(CheckedHistoryIoKindV1::Timeout));
        assert!(matches!(failure.into_error(), AuthorityError::Uncertain));
    }
}
