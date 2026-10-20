//! One exact synthetic HTTPS sink, armed only by actual merged/held predecessors.
//! This is not a SubmissionAuthority or a chain observation. No forwarding,
//! replacement, retry, inclusion, or exposure release is implemented here.
#![cfg(all(test, feature = "synthetic-born-joined-qualification"))]

use super::synthetic_born_provider_v1::SyntheticBornProviderV1;
use crate::host::{
    born_offline_return_owner_v1::RetainedBornMergedTransactionV1,
    financial::born_post_return_inputs_v1::HeldBornPostReturnInputsV1,
};
use crate::{Error, Result};
use prost::Message;
use std::{
    num::NonZeroU32,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use wholepact_chain::SubmissionBackend as _;
use wholepact_chain::{
    SubmissionAttemptOutcome, SubmissionDescriptor, SubmissionDispatchReport, SubmissionPlan,
    SubmissionState,
};
use wholepact_storage_security::EncryptedConnection;
use wholepact_wallet::wallet::{
    synthetic_born_payment_recipient_v1::{
        SyntheticBornPaymentRecipientV1, SyntheticBornRecipientReceiptV1,
    },
    synthetic_born_receiver_blocks_v1::{
        RawTransaction, SendResponse, SyntheticBornReceiverBlocksV1,
    },
};
use zeroize::Zeroizing;

#[derive(Clone, Default)]
pub(super) struct SyntheticSinkControlV1 {
    state: Arc<Mutex<SinkState>>,
    closed: Arc<AtomicBool>,
}
#[derive(Default)]
struct SinkState {
    ever_armed: bool,
    attempts: u32,
    poisoned: bool,
    phase: Phase,
}
#[derive(Default)]
enum Phase {
    #[default]
    Dormant,
    Armed {
        descriptor: SubmissionDescriptor,
        deadline: Instant,
    },
    Received {
        descriptor: SubmissionDescriptor,
        bytes: Zeroizing<Vec<u8>>,
        at: Instant,
    },
    Closed,
}
impl SyntheticSinkControlV1 {
    /// The provider calls this ONLY after its original finite HTTP/TLS/read
    /// guards. No caller can supply an expected descriptor through this API.
    pub(super) fn receive(&self, encoded: &[u8]) -> Option<Vec<u8>> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let mut state = self.state.try_lock().ok()?;
        state.attempts = state.attempts.saturating_add(1);
        let phase = std::mem::replace(&mut state.phase, Phase::Closed);
        let Phase::Armed {
            descriptor,
            deadline,
        } = phase
        else {
            state.poisoned = true;
            return None;
        };
        if state.attempts != 1 || state.poisoned || Instant::now() >= deadline {
            state.poisoned = true;
            return None;
        }
        let checked = (|| {
            let raw = RawTransaction::decode(encoded).ok()?;
            if raw.encode_to_vec() != encoded || raw.height != 0 {
                return None;
            }
            let bytes = Zeroizing::new(raw.data);
            let parsed = SubmissionPlan::new(
                &descriptor.obligation_id,
                &descriptor.proposal_id,
                &descriptor.operation_id,
                &bytes,
            )
            .ok()?;
            if parsed.descriptor() != &descriptor
                || Instant::now() >= deadline
                || self.closed.load(Ordering::Acquire)
            {
                return None;
            }
            Some(bytes)
        })();
        let Some(bytes) = checked else {
            state.poisoned = true;
            return None;
        };
        state.phase = Phase::Received {
            descriptor,
            bytes,
            at: Instant::now(),
        };
        // This response means only: the finite synthetic endpoint received one
        // exact wire transaction. It is never mempool/inclusion/consensus proof.
        Some(
            SendResponse {
                error_code: 0,
                error_message: String::new(),
            }
            .encode_to_vec(),
        )
    }
    fn close(&self) {
        // Immediate close never waits on even the bounded parser and no rearm
        // exists. An in-flight receive past its final flag load may still ACK;
        // dropping this guard cannot yield a retained success owner. A late
        // network outcome remains uncertain in the real submission journal.
        self.closed.store(true, Ordering::Release);
        if let Ok(mut state) = self.state.try_lock() {
            state.phase = Phase::Closed;
        }
    }
}

pub(super) struct ArmedSyntheticBornSubmissionV1<'a, 'held, 'read, 'owner, 'host> {
    provider: &'a SyntheticBornProviderV1,
    original: &'a RetainedBornMergedTransactionV1<'read, 'owner, 'host>,
    inputs: &'a HeldBornPostReturnInputsV1<'held>,
    descriptor: SubmissionDescriptor,
    deadline: Instant,
}
impl SyntheticBornProviderV1 {
    /// Call inside the SAME synchronous all-wallet held callback immediately
    /// before the unchanged real dispatch. No raw descriptor/bytes constructor.
    pub(super) fn arm_original_submission<'a, 'held, 'read, 'owner, 'host>(
        &'a self,
        original: &'a RetainedBornMergedTransactionV1<'read, 'owner, 'host>,
        inputs: &'a HeldBornPostReturnInputsV1<'held>,
    ) -> Result<ArmedSyntheticBornSubmissionV1<'a, 'held, 'read, 'owner, 'host>> {
        let deadline = inputs.monotonic_deadline().min(self.original_deadline());
        inputs.require_original_submission(original)?;
        original.check_current_until(deadline)?;
        inputs.check_current()?;
        let descriptor = original.verified_submission().descriptor().clone();
        let public = self.original_material().fabricated_context();
        if inputs.context().source().endpoint != self.endpoint()
            || inputs.context().tip().height != u64::from(public.tip_height)
            || descriptor.network != "testnet"
            || descriptor.expiry_height <= public.tip_height
            || Instant::now() >= deadline
        {
            return Err(Error::Authentication);
        }
        {
            let mut state = self
                .sink_control()
                .state
                .try_lock()
                .map_err(|_| Error::Permission)?;
            if self.sink_control().closed.load(Ordering::Acquire)
                || state.ever_armed
                || state.attempts != 0
                || state.poisoned
                || !matches!(state.phase, Phase::Dormant)
            {
                return Err(Error::Permission);
            }
            state.ever_armed = true;
            state.phase = Phase::Armed {
                descriptor: descriptor.clone(),
                deadline,
            };
        }
        let guard = ArmedSyntheticBornSubmissionV1 {
            provider: self,
            original,
            inputs,
            descriptor,
            deadline,
        };
        guard.check_current()?;
        Ok(guard)
    }
}
impl ArmedSyntheticBornSubmissionV1<'_, '_, '_, '_, '_> {
    fn check_current(&self) -> Result<()> {
        self.inputs.require_original_submission(self.original)?;
        self.original.check_current_until(self.deadline)?;
        self.inputs.check_current()?;
        if Instant::now() >= self.deadline
            || self.original.verified_submission().descriptor() != &self.descriptor
            || self.inputs.context().source().endpoint != self.provider.endpoint()
            || self.provider.denied_requests() != 0
        {
            return Err(Error::Permission);
        }
        Ok(())
    }
    /// Only an actual successful dispatch report plus the actual one-shot sink
    /// receipt closes this fixture boundary. Any uncertainty remains failure;
    /// neither this method nor Drop changes production journals or exposure.
    pub(super) fn finish(
        self,
        report: &SubmissionDispatchReport,
    ) -> Result<ReceivedSyntheticBornSubmissionV1> {
        self.check_current()?;
        if report.descriptor != self.descriptor
            || !matches!(
                report.attempt.outcome,
                SubmissionAttemptOutcome::Acknowledged
            )
            || !matches!(
                report.historical_provider_state,
                SubmissionState::BackendAcknowledged
            )
            || report.attempt.number != 1
            || report.attempt.source_id != self.inputs.context().source().source_id
            || report.clears_authorization_exposure
            || report.permits_replacement
        {
            return Err(Error::Authentication);
        }
        let agreement = &self.original.original().proposal().manifest().agreement;
        if agreement.recipients.len() != 1 {
            return Err(Error::Invalid);
        }
        let recipient = &agreement.recipients[0];
        let confirmations = NonZeroU32::new(agreement.confirmation_policy.required_confirmations)
            .filter(|count| count.get() <= 32)
            .ok_or(Error::Invalid)?;
        let mut state = self
            .provider
            .sink_control()
            .state
            .try_lock()
            .map_err(|_| Error::Permission)?;
        if state.poisoned || state.attempts != 1 {
            return Err(Error::Authentication);
        }
        let Phase::Received {
            descriptor,
            bytes,
            at,
        } = std::mem::replace(&mut state.phase, Phase::Closed)
        else {
            return Err(Error::Authentication);
        };
        if descriptor != self.descriptor || at >= self.deadline {
            return Err(Error::Authentication);
        }
        drop(state);
        self.check_current()?;
        Ok(ReceivedSyntheticBornSubmissionV1 {
            descriptor,
            bytes,
            material: self.provider.original_material().clone(),
            recipient_address: recipient.address.clone(),
            amount: recipient.amount.as_zatoshis(),
            confirmations,
        })
    }
}
impl Drop for ArmedSyntheticBornSubmissionV1<'_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        self.provider.sink_control().close();
    }
}

/// Public wire received by the actual finite endpoint, never caller-supplied
/// expected bytes. Opaque, non-Clone and nonserializable; no raw byte getter.
pub(super) struct ReceivedSyntheticBornSubmissionV1 {
    descriptor: SubmissionDescriptor,
    bytes: Zeroizing<Vec<u8>>,
    material: Arc<SyntheticBornReceiverBlocksV1>,
    recipient_address: String,
    amount: u64,
    confirmations: NonZeroU32,
}
impl ReceivedSyntheticBornSubmissionV1 {
    /// Run AFTER leaving the held-wallet callback. The receiver was created
    /// before the agreement and must be that same retained owner. Fabricated
    /// inclusion supports decryption testing only, not exposure reconciliation.
    pub(super) fn decrypt_recipient(
        self,
        recipient: &SyntheticBornPaymentRecipientV1,
        connection: EncryptedConnection,
    ) -> Result<SyntheticBornRecipientReceiptV1> {
        if recipient.public_receive_address() != self.recipient_address {
            return Err(Error::Authentication);
        }
        let receipt = recipient
            .scan_received(
                connection,
                &self.material,
                &self.bytes,
                self.amount,
                self.confirmations,
            )
            .map_err(|_| {
                Error::Receipt(
                    "synthetic exact received recipient decryption failed; no exposure release"
                        .into(),
                )
            })?;
        if receipt.transaction_id != self.descriptor.transaction_id
            || receipt.decrypted_zatoshis != self.amount
            || receipt.recipient_address != self.recipient_address
            || receipt.public_network_inclusion_verified
            || receipt.independent_consensus_verified
        {
            return Err(Error::Authentication);
        }
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Inert state-machine metadata only. This cannot construct a merged owner,
    // a held wallet observation, an armed guard or a received receipt owner.
    fn descriptor() -> SubmissionDescriptor {
        SubmissionDescriptor {
            operation_id: "synthetic-sink-negative-operation".into(),
            obligation_id: "synthetic-sink-negative-obligation".into(),
            proposal_id: "synthetic-sink-negative-proposal".into(),
            transaction_id: "11".repeat(32),
            bytes_sha256: "22".repeat(32),
            expiry_height: 4_465_100,
            network: "testnet".into(),
            consensus_branch_id: 0x77190ad9,
        }
    }
    fn inert_armed(deadline: Instant) -> SyntheticSinkControlV1 {
        let control = SyntheticSinkControlV1::default();
        {
            let mut state = control.state.lock().unwrap();
            state.ever_armed = true;
            state.phase = Phase::Armed {
                descriptor: descriptor(),
                deadline,
            };
        }
        control
    }
    #[test]
    fn synthetic_sink_denies_unarmed_expired_malformed_and_duplicate() {
        let raw = RawTransaction {
            data: vec![1, 2, 3],
            height: 0,
        }
        .encode_to_vec();
        let dormant = SyntheticSinkControlV1::default();
        assert!(dormant.receive(&raw).is_none());
        assert!(dormant.state.lock().unwrap().poisoned);
        let expired = inert_armed(Instant::now() - Duration::from_secs(1));
        assert!(expired.receive(&raw).is_none());
        assert!(expired.state.lock().unwrap().poisoned);
        let malformed = inert_armed(Instant::now() + Duration::from_secs(1));
        assert!(malformed.receive(&raw).is_none());
        assert!(malformed.receive(&raw).is_none());
        let state = malformed.state.lock().unwrap();
        assert_eq!(state.attempts, 2);
        assert!(state.poisoned && matches!(state.phase, Phase::Closed));
    }
    #[test]
    fn synthetic_sink_close_never_waits_for_parser_or_reopens() {
        let control = inert_armed(Instant::now() + Duration::from_secs(1));
        let held = control.state.lock().unwrap();
        control.close();
        assert!(control.closed.load(Ordering::Acquire));
        assert!(control.receive(&[]).is_none());
        drop(held);
        control.close();
        assert!(matches!(control.state.lock().unwrap().phase, Phase::Closed));
    }
    #[test]
    fn synthetic_sink_second_send_cannot_acknowledge_or_replace_received_bytes() {
        let control = SyntheticSinkControlV1::default();
        {
            let mut state = control.state.lock().unwrap();
            state.ever_armed = true;
            state.attempts = 1;
            state.phase = Phase::Received {
                descriptor: descriptor(),
                bytes: Zeroizing::new(vec![1]),
                at: Instant::now(),
            };
        }
        assert!(control.receive(&[]).is_none());
        let state = control.state.lock().unwrap();
        assert!(state.poisoned && matches!(state.phase, Phase::Closed));
        assert_eq!(state.attempts, 2);
    }
}

/// Financial qualification adapter. Only the maintained orchestrator can mint
/// PreparedDispatch; arming takes that actual token, never a descriptor DTO.
pub(super) struct SyntheticFinancialSubmissionBackendV1<'a> {
    provider: &'a SyntheticBornProviderV1,
    inner: wholepact_chain::LightwalletSubmissionBackend,
    expected: Option<SubmissionDescriptor>,
}
#[derive(serde::Serialize)]
pub(super) struct SyntheticFinancialSubmissionReceiptV1 {
    pub exact_saved_transaction_received: bool,
    pub received_once: bool,
    pub actual_tls_provider: bool,
    pub public_network_settlement: bool,
}
impl<'a> SyntheticFinancialSubmissionBackendV1<'a> {
    pub(super) fn no_private_submission_observed(&self) -> bool {
        self.expected.is_none()
            && self
                .provider
                .sink_control()
                .state
                .try_lock()
                .is_ok_and(|state| {
                    !state.ever_armed
                        && state.attempts == 0
                        && !state.poisoned
                        && matches!(state.phase, Phase::Dormant)
                })
    }

    pub(super) fn new(
        provider: &'a SyntheticBornProviderV1,
        adapter: wholepact_chain::ChainAdapter,
    ) -> Result<Self> {
        if adapter.identity().endpoint != provider.endpoint()
            || Instant::now() >= provider.original_deadline()
        {
            return Err(Error::Authentication);
        }
        Ok(Self {
            provider,
            inner: wholepact_chain::LightwalletSubmissionBackend::new(adapter),
            expected: None,
        })
    }
    pub(super) fn finish(
        &self,
        report: &SubmissionDispatchReport,
    ) -> Result<SyntheticFinancialSubmissionReceiptV1> {
        let expected = self.expected.as_ref().ok_or(Error::Authentication)?;
        if report.descriptor != *expected
            || !matches!(
                report.attempt.outcome,
                SubmissionAttemptOutcome::Acknowledged
            )
            || !matches!(
                report.historical_provider_state,
                SubmissionState::BackendAcknowledged
            )
            || report.clears_authorization_exposure
            || report.permits_replacement
        {
            return Err(Error::Authentication);
        }
        let state = self
            .provider
            .sink_control()
            .state
            .try_lock()
            .map_err(|_| Error::Permission)?;
        let Phase::Received {
            descriptor,
            bytes,
            at,
        } = &state.phase
        else {
            return Err(Error::Authentication);
        };
        if descriptor != expected
            || bytes.is_empty()
            || state.attempts != 1
            || state.poisoned
            || *at >= self.provider.original_deadline()
        {
            return Err(Error::Authentication);
        }
        Ok(SyntheticFinancialSubmissionReceiptV1 {
            exact_saved_transaction_received: true,
            received_once: true,
            actual_tls_provider: true,
            public_network_settlement: false,
        })
    }
}
impl wholepact_chain::SubmissionBackend for SyntheticFinancialSubmissionBackendV1<'_> {
    fn identity(&self) -> &wholepact_chain::BackendIdentity {
        self.inner.identity()
    }
    fn fresh_context(
        &mut self,
    ) -> wholepact_chain::SubmissionFuture<
        '_,
        std::result::Result<wholepact_chain::ChainContext, wholepact_chain::ChainError>,
    > {
        self.inner.fresh_context()
    }
    fn submit_exact<'a>(
        &'a mut self,
        dispatch: wholepact_chain::PreparedDispatch<'a>,
    ) -> wholepact_chain::SubmissionFuture<
        'a,
        std::result::Result<wholepact_chain::BackendSubmissionResult, wholepact_chain::ChainError>,
    > {
        Box::pin(async move {
            let denied = || wholepact_chain::ChainError::SubmissionNotAuthorized;
            let observed = Instant::now();
            let now = crate::now().map_err(|_| denied())?;
            let remaining = dispatch
                .valid_until_unix_seconds()
                .checked_sub(now)
                .filter(|v| *v > 0)
                .ok_or_else(denied)?;
            let deadline = self.provider.original_deadline().min(
                observed
                    .checked_add(std::time::Duration::from_secs(remaining))
                    .ok_or_else(denied)?,
            );
            let descriptor = dispatch.descriptor().clone();
            if self.expected.is_some()
                || dispatch.backend() != self.inner.identity()
                || dispatch.backend().endpoint != self.provider.endpoint()
                || descriptor.network != "testnet"
                || descriptor.expiry_height
                    <= self
                        .provider
                        .original_material()
                        .fabricated_context()
                        .tip_height
                || Instant::now() >= deadline
            {
                return Err(denied());
            }
            {
                let mut state = self
                    .provider
                    .sink_control()
                    .state
                    .try_lock()
                    .map_err(|_| denied())?;
                if self.provider.sink_control().closed.load(Ordering::Acquire)
                    || state.ever_armed
                    || state.attempts != 0
                    || state.poisoned
                    || !matches!(state.phase, Phase::Dormant)
                {
                    return Err(denied());
                }
                state.ever_armed = true;
                state.phase = Phase::Armed {
                    descriptor: descriptor.clone(),
                    deadline,
                };
            }
            self.expected = Some(descriptor);
            // The unchanged adapter performs its real TLS connect/readiness and
            // final immutable token expiry check before disclosing private bytes.
            self.inner.submit_exact(dispatch).await
        })
    }
}
impl Drop for SyntheticFinancialSubmissionBackendV1<'_> {
    fn drop(&mut self) {
        self.provider.sink_control().close();
    }
}
