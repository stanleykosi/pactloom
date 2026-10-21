//! Actual installed-provider/kernel-peer result lease. Wire evidence is inert;
//! only this authenticated receive path can construct the public lease.
use crate::authority_bridge::{BridgeError, Result, financial_continuation_v1::*};
use crate::{
    account::birth::enrollment::roster_v2::financial_source_v1::{
        FinancialReturnSourcePinV1, PreparedOriginalFinancialSourceV1,
    },
    native_peer::PeerProcess,
    native_ui::financial_authority_v1::{FinancialReadLeaseV1, FinancialReturnActionV1},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinancialResultStageV1 {
    InstalledProviderVerification,
    HostPreparedWrite,
    ReadyWait,
    ReadyMatch,
    FetchWrite,
    HeldRead,
    EvidenceValidation,
    PreviewMatch,
    HeldMatch,
    CurrentLock,
    CurrentPeer,
    CurrentProviderVerification,
    CurrentWrite,
    CurrentRead,
    CurrentMatch,
    FinishWrite,
    FinishRead,
    FinishMatch,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinancialResultErrorClassV1 {
    Binding,
    Conflict,
    Missing,
    Uncertain,
    Limit,
    Permission,
    RecoveryRequired,
    CompleteOriginRecoveryUnavailable,
    Verification,
    SignerOriginUnavailable,
    Journal,
    Authority,
    Wallet,
    Ipc,
}
/// Relative monotonic observations for the same first failing Current call.
/// 2001 means greater than 2000ms; None means that phase was not reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinancialResultCurrentTimingV1 {
    pub budget_ms: u16,
    pub provider_elapsed_ms: Option<u16>,
    pub remaining_before_write_ms: Option<u16>,
    pub remaining_before_read_ms: Option<u16>,
    pub roundtrip_elapsed_ms: u16,
}
fn bounded_elapsed_ms(value: Duration) -> u16 {
    if value > Duration::from_millis(2000) {
        2001
    } else {
        value.as_millis() as u16
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinancialResultDiagnosticV1 {
    pub current_timing: Option<FinancialResultCurrentTimingV1>,
    pub stage: FinancialResultStageV1,
    pub error_class: FinancialResultErrorClassV1,
    pub frame_cause: Option<wholepact_signer_origin::framing::FrameReadCause>,
}
#[derive(Debug)]
pub struct FinancialResultObservedErrorV1 {
    pub error: BridgeError,
    pub diagnostic: Option<FinancialResultDiagnosticV1>,
}
struct FinancialResultObserverV1 {
    timing: std::cell::Cell<Option<FinancialResultCurrentTimingV1>>,
    stage: std::cell::Cell<FinancialResultStageV1>,
    frame: std::cell::Cell<Option<wholepact_signer_origin::framing::FrameReadCause>>,
}
impl FinancialResultObserverV1 {
    fn new(stage: FinancialResultStageV1) -> Self {
        Self {
            timing: std::cell::Cell::new(None),
            stage: std::cell::Cell::new(stage),
            frame: std::cell::Cell::new(None),
        }
    }
    fn at(&self, stage: FinancialResultStageV1) {
        self.stage.set(stage);
        self.frame.set(None);
    }
    fn diagnostic(&self, error: &BridgeError) -> FinancialResultDiagnosticV1 {
        use FinancialResultErrorClassV1 as C;
        let error_class = match error {
            BridgeError::Binding => C::Binding,
            BridgeError::Conflict => C::Conflict,
            BridgeError::Missing => C::Missing,
            BridgeError::Uncertain => C::Uncertain,
            BridgeError::Limit => C::Limit,
            BridgeError::Permission => C::Permission,
            BridgeError::RecoveryRequired => C::RecoveryRequired,
            BridgeError::CompleteOriginRecoveryUnavailable => C::CompleteOriginRecoveryUnavailable,
            BridgeError::Verification => C::Verification,
            BridgeError::SignerOriginUnavailable => C::SignerOriginUnavailable,
            BridgeError::Journal(_) => C::Journal,
            BridgeError::Authority(_) => C::Authority,
            BridgeError::Wallet(_) => C::Wallet,
            BridgeError::Ipc => C::Ipc,
        };
        FinancialResultDiagnosticV1 {
            current_timing: self.timing.get(),
            stage: self.stage.get(),
            error_class,
            frame_cause: self.frame.get(),
        }
    }
    fn error(&self, error: BridgeError) -> FinancialResultObservedErrorV1 {
        FinancialResultObservedErrorV1 {
            diagnostic: Some(self.diagnostic(&error)),
            error,
        }
    }
}
#[path = "financial_result_ipc_v1/retained_original_v3.rs"]
mod retained_original_v3;
pub use retained_original_v3::FinancialResultRestrictionV1;
use retained_original_v3::{OriginalResultRestrictionsV1, read_restricted_observed, read_setup_restricted_observed, write_restricted};

const MAX_FRAME: usize = 512 * 1024;
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinancialResultRequestV1 {
    pub account_id: String,
    pub authorization_id: String,
    pub original_consent_ref: String,
    pub fixed: FixedProposalIdentityV1,
}
impl FinancialResultRequestV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        crate::authority_bridge::born_history_ipc::hash(&self.account_id)?;
        crate::authority_bridge::born_history_ipc::hash(&self.original_consent_ref)?;
        crate::review::validate_label(&self.authorization_id).map_err(|_| BridgeError::Binding)?;
        crate::authority_bridge::durable_review_ipc_v3::fixed_binding_v3(&self.fixed)?
            .validate()?;
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    request: FinancialResultRequestV1,
    continuation: OwnerControlRequest,
    record: FinancialContinuationRecordV1,
    result_digest: String,
    outbox_digest: String,
    participant_index: usize,
    signature_set_digest: String,
    outbox: String,
}
impl Evidence {
    fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.record
            .validate_request(&self.continuation, &self.record.terms.scope.witness)?;
        let a = &self.record.terms.scope.authorization;
        if self.request.account_id != a.identity.account_id
            || self.request.authorization_id != a.authorization_id
            || crate::authority_bridge::durable_review_ipc_v3::fixed_binding_v3(
                &self.request.fixed,
            )? != a.fixed
            || self.outbox.len() > crate::authority_bridge::protocol::MAX_OUTBOX_BYTES
            || hex::encode(Sha256::digest(self.outbox.as_bytes())) != self.outbox_digest
        {
            return Err(BridgeError::Binding);
        }
        if signature_digest(&self.outbox, self.participant_index)? != self.signature_set_digest {
            return Err(BridgeError::Binding);
        }
        crate::authority_bridge::born_history_ipc::hash(&self.result_digest)?;
        crate::authority_bridge::born_history_ipc::hash(&self.outbox_digest)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Response {
    Preview {
        preview: PreviewData,
    },
    Ready {
        lease_id: String,
    },
    Held {
        lease_id: String,
        remaining_ms: u64,
        evidence: Box<Evidence>,
    },
    Current {
        lease_id: String,
        nonce: String,
    },
    Finished,
    Denied,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    HostPrepared { preview_digest: String },
    Fetch { lease_id: String },
    Check { nonce: String },
    Finish,
}
fn read<T: serde::de::DeserializeOwned>(
    stream: &UnixStream,
    peer: &PeerProcess,
    deadline: Instant,
    check: &dyn Fn() -> Result<()>,
) -> Result<T> {
    read_observed(stream, peer, deadline, check, None)
}
fn read_observed<T: serde::de::DeserializeOwned>(
    stream: &UnixStream,
    peer: &PeerProcess,
    deadline: Instant,
    check: &dyn Fn() -> Result<()>,
    observer: Option<&FinancialResultObserverV1>,
) -> Result<T> {
    read_restricted_observed(stream, peer, deadline, check, observer, None)
}
// Only inert preview / HostPrepared / READY frames use the setup budget.
// Actual payload, Fetch, Current and Finish remain on the strict action reader.
fn read_setup<T: serde::de::DeserializeOwned>(
    stream: &UnixStream,
    peer: &PeerProcess,
    deadline: Instant,
    check: &dyn Fn() -> Result<()>,
) -> Result<T> {
    read_setup_observed(stream, peer, deadline, check, None)
}
fn read_setup_observed<T: serde::de::DeserializeOwned>(
    stream: &UnixStream,
    peer: &PeerProcess,
    deadline: Instant,
    check: &dyn Fn() -> Result<()>,
    observer: Option<&FinancialResultObserverV1>,
) -> Result<T> {
    read_setup_restricted_observed(stream, peer, deadline, check, observer, None)
}
fn write<T: Serialize>(
    stream: &mut UnixStream,
    data: &T,
    deadline: Instant,
    check: &dyn Fn() -> Result<()>,
) -> Result<()> {
    crate::authority_bridge::durable_review_ipc_v1::bounded_write(stream, data, deadline, check)
}

/// Actual source + exact retained bytes + observed recipient, awaiting a fresh
/// ReturnExact native decision. It is not a public evidence constructor.
pub(crate) struct PreparedFinancialReturnV1 {
    source_pin: FinancialReturnSourcePinV1,
    setup_deadline: Instant,
    source: Arc<PreparedOriginalFinancialSourceV1>,
    peer: PeerProcess,
    evidence: Evidence,
    digest: String,
}
impl PreparedFinancialReturnV1 {
    pub(crate) fn prepare(
        source: Arc<PreparedOriginalFinancialSourceV1>,
        read_owner: FinancialReadLeaseV1,
        peer: PeerProcess,
        request: &FinancialResultRequestV1,
        stream: &mut UnixStream,
    ) -> Result<Self> {
        request.validate()?;
        let setup_deadline = source
            .original_deadline()
            .min(Instant::now() + Duration::from_secs(900));
        source
            .check_retained_financial_peer_v1(&peer)
            .map_err(|_| BridgeError::Permission)?;
        read_owner
            .check_source(source.identity_digest())
            .map_err(|_| BridgeError::Permission)?;
        peer.check_alive().map_err(|_| BridgeError::Permission)?;
        let (original, _, _, result, journal_pin, continuation) = source
            .financial_journal()
            .map_err(|_| BridgeError::Permission)?
            .financial_retained_result_v1(
                &*source
                    .financial_binding()
                    .map_err(|_| BridgeError::Permission)?,
                &read_owner,
            )?;
        read_owner
            .check_source(source.identity_digest())
            .map_err(|_| BridgeError::Permission)?;
        source
            .check_retained_financial_peer_v1(&peer)
            .map_err(|_| BridgeError::Permission)?;
        let OwnerControl::AdmitFinancialContinuationV1 { record } = &continuation.control else {
            return Err(BridgeError::Binding);
        };
        if original.original_consent().reference() != request.original_consent_ref
            || result.original_consent_ref != request.original_consent_ref
            || result.authorization_id != request.authorization_id
        {
            return Err(BridgeError::Binding);
        }
        let participant_index = original
            .accepted_manifest()
            .proposal_input()
            .manifest
            .participants
            .iter()
            .position(|p| p.account_id == request.account_id)
            .ok_or(BridgeError::Binding)?;
        let signature_set_digest = signature_digest(&result.outbox_payload, participant_index)?;
        let evidence = Evidence {
            participant_index,
            signature_set_digest,
            request: request.clone(),
            record: record.as_ref().clone(),
            continuation,
            result_digest: result.result_digest.clone(),
            outbox_digest: result.outbox_digest.clone(),
            outbox: result.outbox_payload.clone(),
        };
        evidence.validate()?;
        if journal_pin.result_digest() != evidence.result_digest {
            return Err(BridgeError::Binding);
        }
        let source_pin = source
            .prepare_financial_return_source_pin_v1(journal_pin, &peer)
            .map_err(|_| BridgeError::Permission)?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:financial-exact-result-return:v1",
            &(
                source.identity_digest(),
                peer.instance(),
                PreviewData::from_evidence(&evidence),
            ),
        )
        .map_err(|_| BridgeError::Binding)?;
        let observed = PeerProcess::observe(stream).map_err(|_| BridgeError::Permission)?;
        peer.same_live_process(&observed)
            .map_err(|_| BridgeError::Permission)?;
        let preview = PreviewData::from_evidence(&evidence);
        write(
            stream,
            &Response::Preview { preview },
            source
                .original_deadline()
                .min(Instant::now() + Duration::from_secs(2)),
            &|| {
                read_owner
                    .check_source(source.identity_digest())
                    .and_then(|_| source.check_financial_return_source_pin_v1(&source_pin, &peer))
                    .and_then(|_| read_owner.check_current())
                    .map_err(|_| BridgeError::Permission)
            },
        )?;
        read_owner
            .check_source(source.identity_digest())
            .map_err(|_| BridgeError::Permission)?;
        source
            .check_financial_return_source_pin_v1(&source_pin, &peer)
            .map_err(|_| BridgeError::Permission)?;
        read_owner
            .check_source(source.identity_digest())
            .map_err(|_| BridgeError::Permission)?;
        drop(read_owner);
        Ok(Self {
            source_pin,
            setup_deadline,
            source,
            peer,
            evidence,
            digest,
        })
    }
    /// Wait with inert prepared data only. Do not stage the short native review
    /// until the Host has completed its own exact retention preflight.
    pub(crate) fn await_host_prepared(self, stream: &UnixStream) -> Result<Self> {
        let deadline = self.setup_deadline.min(self.source.original_deadline());
        let current = || {
            self.source
                .check_financial_return_source_pin_v1(&self.source_pin, &self.peer)
                .map_err(|_| BridgeError::Permission)
        };
        let expected = PreviewData::from_evidence(&self.evidence).digest()?;
        match read_setup(stream, &self.peer, deadline, &current)? {
            Command::HostPrepared { preview_digest } if preview_digest == expected => {
                current()?;
                Ok(self)
            }
            _ => Err(BridgeError::Permission),
        }
    }
    pub(crate) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(crate) fn display(&self) -> String {
        format!(
            "RETURN ONLY THE ALREADY RETAINED EXACT FINANCIAL SIGNATURE RESULT\nAccount: {}\nAuthorization: {}\nOriginal consent: {}\nResult: {}\nOutbox: {}\nRecipient process: {}\nNo new signature, reservation, or transaction will be created.\nExact return: {}",
            self.evidence.request.account_id,
            self.evidence.request.authorization_id,
            self.evidence.request.original_consent_ref,
            self.evidence.result_digest,
            self.evidence.outbox_digest,
            self.peer.instance(),
            self.digest
        )
    }
    pub(crate) fn approve(
        self,
        action: FinancialReturnActionV1,
    ) -> Result<ApprovedFinancialReturnV1> {
        action
            .check_source(self.source.identity_digest())
            .map_err(|_| BridgeError::Permission)?;
        self.source
            .check_financial_return_source_pin_v1(&self.source_pin, &self.peer)
            .map_err(|_| BridgeError::Permission)?;
        action
            .check_source(self.source.identity_digest())
            .map_err(|_| BridgeError::Permission)?;
        if action.terms_digest() != self.digest {
            return Err(BridgeError::Binding);
        }
        Ok(ApprovedFinancialReturnV1 {
            prepared: self,
            action,
        })
    }
}
pub(crate) struct ApprovedFinancialReturnV1 {
    prepared: PreparedFinancialReturnV1,
    action: FinancialReturnActionV1,
}
impl ApprovedFinancialReturnV1 {
    fn check(&self) -> Result<()> {
        self.action
            .check_source(self.prepared.source.identity_digest())
            .map_err(|_| BridgeError::Permission)?;
        self.prepared
            .source
            .check_financial_return_source_pin_v1(&self.prepared.source_pin, &self.prepared.peer)
            .map_err(|_| BridgeError::Permission)?;
        self.action
            .check_source(self.prepared.source.identity_digest())
            .map_err(|_| BridgeError::Permission)
    }
    pub(crate) fn serve(self, mut stream: UnixStream) -> Result<()> {
        self.check()?;
        let observed = PeerProcess::observe(&stream).map_err(|_| BridgeError::Permission)?;
        self.prepared
            .peer
            .same_live_process(&observed)
            .map_err(|_| BridgeError::Permission)?;
        let deadline = self
            .action
            .binding()
            .bounded_deadline()
            .map_err(|_| BridgeError::Permission)?
            .min(self.prepared.source.original_deadline());
        let lease_id = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?);
        // Borrow evidence while serializing so no duplicate secret-bearing copy
        // is minted and no later retry can reconstruct a different payload.
        #[derive(Serialize)]
        struct Held<'a> {
            status: &'static str,
            lease_id: &'a str,
            remaining_ms: u64,
            evidence: &'a Evidence,
        }
        write(
            &mut stream,
            &Response::Ready {
                lease_id: lease_id.clone(),
            },
            deadline,
            &|| self.check(),
        )?;
        match read(&stream, &self.prepared.peer, deadline, &|| self.check())? {
            Command::Fetch { lease_id: actual } if actual == lease_id => (),
            _ => return Err(BridgeError::Permission),
        }
        let remaining_ms = u64::try_from(
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )
        .map_err(|_| BridgeError::Permission)?;
        if remaining_ms == 0 || remaining_ms > 120_000 {
            return Err(BridgeError::Permission);
        }
        write(
            &mut stream,
            &Held {
                status: "held",
                lease_id: &lease_id,
                remaining_ms,
                evidence: &self.prepared.evidence,
            },
            deadline,
            &|| self.check(),
        )?;
        loop {
            let command: Command = read(&stream, &self.prepared.peer, deadline, &|| self.check())?;
            self.check()?;
            match command {
                Command::Check { nonce } => {
                    crate::authority_bridge::born_history_ipc::hash(&nonce)?;
                    write(
                        &mut stream,
                        &Response::Current {
                            lease_id: lease_id.clone(),
                            nonce,
                        },
                        deadline,
                        &|| self.check(),
                    )?;
                }
                Command::Finish => {
                    write(&mut stream, &Response::Finished, deadline, &|| self.check())?;
                    return Ok(());
                }
                Command::Fetch { .. } | Command::HostPrepared { .. } => {
                    return Err(BridgeError::Permission);
                }
            }
        }
    }
}

/// Owns the actual installed trust anchor and checked kernel peer, not an old
/// signing lease or a caller-asserted delivery record. No Clone/serde constructor.
pub struct AuthenticatedFinancialResultLeaseV1 {
    original_restrictions: Option<OriginalResultRestrictionsV1>,
    diagnostic: Mutex<Option<FinancialResultDiagnosticV1>>,
    provider: crate::authority_bridge::provider::InstalledSignerProvider,
    peer: PeerProcess,
    stream: Mutex<UnixStream>,
    failed: AtomicBool,
    lease_id: String,
    evidence: Evidence,
    deadline: Instant,
}
impl AuthenticatedFinancialResultLeaseV1 {
    pub fn receive(
        provider: crate::authority_bridge::provider::InstalledSignerProvider,
        socket: &Path,
        request: &FinancialResultRequestV1,
        original_deadline: Instant,
    ) -> Result<Self> {
        PreparedFinancialResultReceiverV1::prepare(provider, socket, request, original_deadline)?
            .receive()
    }
    pub fn check_current(&self) -> Result<()> {
        let started = Instant::now();
        let observer = FinancialResultObserverV1::new(FinancialResultStageV1::CurrentPeer);
        let deadline = self.deadline.min(started + Duration::from_secs(2));
        let mut timing = FinancialResultCurrentTimingV1 {
            budget_ms: bounded_elapsed_ms(deadline.saturating_duration_since(started)),
            provider_elapsed_ms: None,
            remaining_before_write_ms: None,
            remaining_before_read_ms: None,
            roundtrip_elapsed_ms: 0,
        };
        let current = || {
            if self.failed.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(BridgeError::Permission);
            }
            self.peer.check_alive().map_err(|_| BridgeError::Permission)?;
            self.original_restrictions.as_ref().map_or(Ok(()), |r| r.check())
        };
        let restriction = || self.original_restrictions.as_ref().map_or(Ok(()), |r| r.check());
        let final_check = self.original_restrictions.as_ref().map(|_| &restriction as &dyn Fn() -> Result<()>);
        let result = (|| {
            restriction()?;
            current()?;
            observer.at(FinancialResultStageV1::CurrentLock);
            let mut stream =
                crate::authority_bridge::born_ipc_io::lock_until(&self.stream, deadline, &current)?;
            observer.at(FinancialResultStageV1::CurrentProviderVerification);
            let provider_started = Instant::now();
            let actual = self.provider.verify_server(&stream);
            timing.provider_elapsed_ms = Some(bounded_elapsed_ms(provider_started.elapsed()));
            let actual = actual?;
            observer.at(FinancialResultStageV1::CurrentPeer);
            self.peer
                .same_live_process(&actual)
                .map_err(|_| BridgeError::Permission)?;
            let nonce = hex::encode(crate::vault::random::<32>().map_err(|_| BridgeError::Ipc)?);
            observer.at(FinancialResultStageV1::CurrentWrite);
            timing.remaining_before_write_ms = Some(bounded_elapsed_ms(
                deadline.saturating_duration_since(Instant::now()),
            ));
            write_restricted(
                &mut stream,
                &Command::Check {
                    nonce: nonce.clone(),
                },
                deadline,
                &current,
                final_check,
            )?;
            observer.at(FinancialResultStageV1::CurrentRead);
            timing.remaining_before_read_ms = Some(bounded_elapsed_ms(
                deadline.saturating_duration_since(Instant::now()),
            ));
            let response = read_restricted_observed(&stream, &self.peer, deadline, &current, Some(&observer), final_check)?;
            observer.at(FinancialResultStageV1::CurrentMatch);
            match response {
                Response::Current {
                    lease_id,
                    nonce: actual,
                } if lease_id == self.lease_id && nonce == actual => current(),
                _ => Err(BridgeError::Permission),
            }
        })();
        if let Err(ref error) = result {
            timing.roundtrip_elapsed_ms = bounded_elapsed_ms(started.elapsed());
            observer.timing.set(Some(timing));
            if let Ok(mut diagnostic) = self.diagnostic.lock() {
                if diagnostic.is_none() {
                    *diagnostic = Some(observer.diagnostic(error));
                }
            }
            self.failed.store(true, Ordering::Release);
        }
        result
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub fn last_failure_v1(&self) -> Option<FinancialResultDiagnosticV1> {
        self.diagnostic.lock().ok().and_then(|v| *v)
    }
    /// Call only after the consumer's durable exact-intake commit. A missing
    /// reply is uncertain acknowledgement, never permission to sign again.
    pub fn finish(self) -> Result<()> {
        self.finish_kernel(&FinancialResultObserverV1::new(
            FinancialResultStageV1::CurrentPeer,
        ))
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub fn finish_observed_v1(self) -> std::result::Result<(), FinancialResultObservedErrorV1> {
        let observer = FinancialResultObserverV1::new(FinancialResultStageV1::CurrentPeer);
        self.finish_kernel(&observer)
            .map_err(|error| observer.error(error))
    }
    fn finish_kernel(self, observer: &FinancialResultObserverV1) -> Result<()> {
        if let Err(error) = self.check_current() {
            if let Ok(value) = self.diagnostic.lock() {
                if let Some(diagnostic) = *value {
                    observer.stage.set(diagnostic.stage);
                    observer.frame.set(diagnostic.frame_cause);
                    observer.timing.set(diagnostic.current_timing);
                }
            }
            return Err(error);
        }
        let deadline = self.deadline.min(Instant::now() + Duration::from_secs(2));
        let mut stream = self.stream.into_inner().map_err(|_| BridgeError::Ipc)?;
        let current = || {
            if Instant::now() >= deadline {
                return Err(BridgeError::Permission);
            }
            self.peer.check_alive().map_err(|_| BridgeError::Permission)?;
            self.original_restrictions.as_ref().map_or(Ok(()), |r| r.check())
        };
        let restriction = || self.original_restrictions.as_ref().map_or(Ok(()), |r| r.check());
        let final_check = self.original_restrictions.as_ref().map(|_| &restriction as &dyn Fn() -> Result<()>);
        observer.at(FinancialResultStageV1::FinishWrite);
        write_restricted(&mut stream, &Command::Finish, deadline, &current, final_check)?;
        observer.at(FinancialResultStageV1::FinishRead);
        let response = read_restricted_observed(&stream, &self.peer, deadline, &current, Some(observer), final_check)?;
        observer.at(FinancialResultStageV1::FinishMatch);
        match response {
            Response::Finished => Ok(()),
            _ => Err(BridgeError::Uncertain),
        }
    }
    pub fn account_id(&self) -> &str {
        &self.evidence.request.account_id
    }
    pub fn authorization_id(&self) -> &str {
        &self.evidence.request.authorization_id
    }
    pub fn original_consent_ref(&self) -> &str {
        &self.evidence.request.original_consent_ref
    }
    pub fn fixed_identity(&self) -> &FixedProposalIdentityV1 {
        &self.evidence.request.fixed
    }
    pub fn result_digest(&self) -> &str {
        &self.evidence.result_digest
    }
    pub fn outbox_digest(&self) -> &str {
        &self.evidence.outbox_digest
    }
    pub fn continuation_request(&self) -> &OwnerControlRequest {
        &self.evidence.continuation
    }
    pub fn continuation_record(&self) -> &FinancialContinuationRecordV1 {
        &self.evidence.record
    }
    pub fn outbox_bytes(&self) -> Result<&[u8]> {
        self.check_current()?;
        Ok(self.evidence.outbox.as_bytes())
    }
}

impl Drop for Evidence {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.outbox.zeroize();
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PreviewData {
    request: FinancialResultRequestV1,
    continuation: OwnerControlRequest,
    record: FinancialContinuationRecordV1,
    result_digest: String,
    outbox_digest: String,
    signature_set_digest: String,
}
impl PreviewData {
    fn from_evidence(e: &Evidence) -> Self {
        Self {
            request: e.request.clone(),
            continuation: e.continuation.clone(),
            record: e.record.clone(),
            result_digest: e.result_digest.clone(),
            outbox_digest: e.outbox_digest.clone(),
            signature_set_digest: e.signature_set_digest.clone(),
        }
    }
    fn digest(&self) -> Result<String> {
        wholepact_core::proposal::canonical_digest("wholepact:financial-result-preview:v1", self)
            .map_err(|_| BridgeError::Binding)
    }
    fn validate(&self) -> Result<()> {
        self.request.validate()?;
        self.record
            .validate_request(&self.continuation, &self.record.terms.scope.witness)?;
        let a = &self.record.terms.scope.authorization;
        if self.request.account_id != a.identity.account_id
            || self.request.authorization_id != a.authorization_id
            || crate::authority_bridge::durable_review_ipc_v3::fixed_binding_v3(
                &self.request.fixed,
            )? != a.fixed
        {
            return Err(BridgeError::Binding);
        }
        for h in [
            &self.result_digest,
            &self.outbox_digest,
            &self.signature_set_digest,
        ] {
            crate::authority_bridge::born_history_ipc::hash(h)?;
        }
        Ok(())
    }
}
/// Authenticated, inert metadata only. No signature bytes, live grant, or DTO
/// constructor. It may cross the Host's human review without a Signer action.
pub struct AuthenticatedFinancialResultPreviewV1 {
    data: PreviewData,
}
impl AuthenticatedFinancialResultPreviewV1 {
    pub fn account_id(&self) -> &str {
        &self.data.request.account_id
    }
    pub fn authorization_id(&self) -> &str {
        &self.data.request.authorization_id
    }
    pub fn original_consent_ref(&self) -> &str {
        &self.data.request.original_consent_ref
    }
    pub fn fixed_identity(&self) -> &FixedProposalIdentityV1 {
        &self.data.request.fixed
    }
    pub fn result_digest(&self) -> &str {
        &self.data.result_digest
    }
    pub fn outbox_digest(&self) -> &str {
        &self.data.outbox_digest
    }
    pub fn signature_set_digest(&self) -> &str {
        &self.data.signature_set_digest
    }
    pub fn continuation_request(&self) -> &OwnerControlRequest {
        &self.data.continuation
    }
    pub fn continuation_record(&self) -> &FinancialContinuationRecordV1 {
        &self.data.record
    }
}
pub struct PreparedFinancialResultReceiverV1 {
    original_restrictions: Option<OriginalResultRestrictionsV1>,
    setup_deadline: Instant,
    provider: crate::authority_bridge::provider::InstalledSignerProvider,
    peer: PeerProcess,
    stream: UnixStream,
    preview: AuthenticatedFinancialResultPreviewV1,
    original_deadline: Instant,
}
impl PreparedFinancialResultReceiverV1 {
    pub fn prepare(
        provider: crate::authority_bridge::provider::InstalledSignerProvider,
        socket: &Path,
        request: &FinancialResultRequestV1,
        original_deadline: Instant,
    ) -> Result<Self> {
        request.validate()?;
        let deadline = original_deadline.min(Instant::now() + Duration::from_secs(900));
        let mut stream =
            wholepact_signer_origin::connect_local_checked_until(socket, deadline, || {
                if Instant::now() < deadline {
                    Ok(())
                } else {
                    Err(wholepact_signer_origin::Error::Permission)
                }
            })?;
        crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_| BridgeError::Ipc)?;
        let peer = provider.verify_server(&stream)?;
        let current = || peer.check_alive().map_err(|_| BridgeError::Permission);
        write(
            &mut stream,
            &serde_json::json!({"command":"financial_result_v1","schema_version":1,"request":request}),
            deadline.min(Instant::now() + Duration::from_secs(120)),
            &current,
        )?;
        let Response::Preview { preview } = read_setup(&stream, &peer, deadline, &current)? else {
            return Err(BridgeError::Permission);
        };
        preview.validate()?;
        if preview.request != *request {
            return Err(BridgeError::Binding);
        }
        Ok(Self {
            original_restrictions: None,
            setup_deadline: deadline,
            provider,
            peer,
            stream,
            preview: AuthenticatedFinancialResultPreviewV1 { data: preview },
            original_deadline,
        })
    }
    pub fn preview(&self) -> &AuthenticatedFinancialResultPreviewV1 {
        &self.preview
    }
    /// Host preflight must finish before asking the Signer to make ReturnExact.
    /// No saved preview itself grants receive, key use, or dispatch permission.
    pub fn receive(self) -> Result<AuthenticatedFinancialResultLeaseV1> {
        self.receive_kernel(&FinancialResultObserverV1::new(
            FinancialResultStageV1::InstalledProviderVerification,
        ))
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub fn receive_observed_v1(
        self,
    ) -> std::result::Result<AuthenticatedFinancialResultLeaseV1, FinancialResultObservedErrorV1>
    {
        let observer =
            FinancialResultObserverV1::new(FinancialResultStageV1::InstalledProviderVerification);
        self.receive_kernel(&observer)
            .map_err(|error| observer.error(error))
    }
    fn receive_kernel(
        mut self,
        observer: &FinancialResultObserverV1,
    ) -> Result<AuthenticatedFinancialResultLeaseV1> {
        let deadline = self.setup_deadline.min(self.original_deadline);
        let current = || {
            self.peer.check_alive().map_err(|_| BridgeError::Permission)?;
            self.original_restrictions.as_ref().map_or(Ok(()), |r| r.check())
        };
        let restriction = || self.original_restrictions.as_ref().map_or(Ok(()), |r| r.check());
        let final_check = self.original_restrictions.as_ref().map(|_| &restriction as &dyn Fn() -> Result<()>);
        restriction()?;
        observer.at(FinancialResultStageV1::InstalledProviderVerification);
        let actual = self.provider.verify_server(&self.stream)?;
        self.peer
            .same_live_process(&actual)
            .map_err(|_| BridgeError::Permission)?;
        observer.at(FinancialResultStageV1::HostPreparedWrite);
        write_restricted(
            &mut self.stream,
            &Command::HostPrepared {
                preview_digest: self.preview.data.digest()?,
            },
            deadline.min(Instant::now() + Duration::from_secs(120)),
            &current,
            final_check,
        )?;
        observer.at(FinancialResultStageV1::ReadyWait);
        let response =
            read_setup_restricted_observed(&self.stream, &self.peer, deadline, &current, Some(observer), final_check)?;
        observer.at(FinancialResultStageV1::ReadyMatch);
        let Response::Ready { lease_id: ready } = response else {
            return Err(BridgeError::Permission);
        };
        observer.at(FinancialResultStageV1::ReadyMatch);
        crate::authority_bridge::born_history_ipc::hash(&ready)?;
        let started = Instant::now();
        let deadline = self
            .original_deadline
            .min(started + Duration::from_secs(120));
        observer.at(FinancialResultStageV1::FetchWrite);
        write_restricted(
            &mut self.stream,
            &Command::Fetch {
                lease_id: ready.clone(),
            },
            deadline,
            &current,
            final_check,
        )?;
        observer.at(FinancialResultStageV1::HeldRead);
        let response = read_restricted_observed(&self.stream, &self.peer, deadline, &current, Some(observer), final_check)?;
        observer.at(FinancialResultStageV1::HeldMatch);
        let Response::Held {
            lease_id,
            remaining_ms,
            evidence,
        } = response
        else {
            return Err(BridgeError::Permission);
        };
        observer.at(FinancialResultStageV1::EvidenceValidation);
        evidence.validate()?;
        observer.at(FinancialResultStageV1::HeldMatch);
        if lease_id != ready || remaining_ms == 0 || remaining_ms > 120_000 {
            return Err(BridgeError::Binding);
        }
        observer.at(FinancialResultStageV1::PreviewMatch);
        if PreviewData::from_evidence(&evidence) != self.preview.data {
            return Err(BridgeError::Binding);
        }
        let deadline = deadline.min(started + Duration::from_millis(remaining_ms));
        let lease = AuthenticatedFinancialResultLeaseV1 {
            original_restrictions: self.original_restrictions,
            diagnostic: Mutex::new(None),
            provider: self.provider,
            peer: self.peer,
            stream: Mutex::new(self.stream),
            failed: AtomicBool::new(false),
            lease_id,
            evidence: *evidence,
            deadline,
        };
        if let Err(error) = lease.check_current() {
            if let Ok(value) = lease.diagnostic.lock() {
                if let Some(diagnostic) = *value {
                    observer.stage.set(diagnostic.stage);
                    observer.frame.set(diagnostic.frame_cause);
                    observer.timing.set(diagnostic.current_timing);
                }
            }
            return Err(error);
        }
        Ok(lease)
    }
}
fn signature_digest(outbox: &str, participant_index: usize) -> Result<String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Signature {
        action_index: usize,
        signature_hex: String,
    }
    impl Drop for Signature {
        fn drop(&mut self) {
            use zeroize::Zeroize;
            self.signature_hex.zeroize();
        }
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        schema_version: u16,
        candidate_id: String,
        manifest_digest: String,
        proved_artifact_digest: String,
        review_binding: String,
        account_id: String,
        signatures: Vec<Signature>,
    }
    let mut payload: Payload = wholepact_core::strict_json::parse_typed_json_with_byte_limit(
        outbox.as_bytes(),
        crate::authority_bridge::protocol::MAX_OUTBOX_BYTES,
    )
    .map_err(|_| BridgeError::Binding)?;
    if payload.schema_version != 1 || payload.signatures.is_empty() || payload.signatures.len() > 8
    {
        return Err(BridgeError::Binding);
    }
    let _ = (
        &payload.candidate_id,
        &payload.manifest_digest,
        &payload.proved_artifact_digest,
        &payload.review_binding,
        &payload.account_id,
    );
    payload.signatures.sort_by_key(|s| s.action_index);
    if payload
        .signatures
        .windows(2)
        .any(|w| w[0].action_index == w[1].action_index)
    {
        return Err(BridgeError::Binding);
    }
    let mut hash = Sha256::new();
    for sig in &payload.signatures {
        let bytes = zeroize::Zeroizing::new(
            hex::decode(&sig.signature_hex).map_err(|_| BridgeError::Binding)?,
        );
        if bytes.len() != 64 {
            return Err(BridgeError::Binding);
        }
        hash.update((participant_index as u64).to_le_bytes());
        hash.update((sig.action_index as u64).to_le_bytes());
        hash.update(bytes.as_slice());
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn current_timing_bounds_and_unreached_phases_are_explicit() {
        assert_eq!(bounded_elapsed_ms(Duration::ZERO), 0);
        assert_eq!(bounded_elapsed_ms(Duration::from_millis(2000)), 2000);
        assert_eq!(
            bounded_elapsed_ms(Duration::from_millis(2000) + Duration::from_nanos(1)),
            2001
        );
        let observer =
            FinancialResultObserverV1::new(FinancialResultStageV1::CurrentProviderVerification);
        let timing = FinancialResultCurrentTimingV1 {
            budget_ms: 2000,
            provider_elapsed_ms: Some(2001),
            remaining_before_write_ms: None,
            remaining_before_read_ms: None,
            roundtrip_elapsed_ms: 2001,
        };
        observer.timing.set(Some(timing));
        assert_eq!(
            observer
                .diagnostic(&BridgeError::SignerOriginUnavailable)
                .current_timing,
            Some(timing)
        );
    }
    #[test]
    fn finite_observer_preserves_error_and_frame_cause() {
        let observer = FinancialResultObserverV1::new(FinancialResultStageV1::HeldRead);
        observer.frame.set(Some(
            wholepact_signer_origin::framing::FrameReadCause::Deadline,
        ));
        let observed = observer.error(BridgeError::Ipc);
        assert!(matches!(observed.error, BridgeError::Ipc));
        assert_eq!(
            observed.diagnostic,
            Some(FinancialResultDiagnosticV1 {
                current_timing: None,
                stage: FinancialResultStageV1::HeldRead,
                error_class: FinancialResultErrorClassV1::Ipc,
                frame_cause: Some(wholepact_signer_origin::framing::FrameReadCause::Deadline),
            })
        );
        observer.at(FinancialResultStageV1::EvidenceValidation);
        assert_eq!(observer.diagnostic(&BridgeError::Binding).frame_cause, None);
        assert_eq!(
            observer.diagnostic(&BridgeError::Binding).error_class,
            FinancialResultErrorClassV1::Binding
        );
    }
}
