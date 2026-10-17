//! Concrete exact-byte born dispatch. This child alone can borrow the actual
//! merged predecessor's private retention state. The wallet's synchronous held
//! callback remains alive across BOTH submission retention and awaited dispatch.
use super::*;
use crate::host::financial::born_post_return_inputs_v1::HeldBornPostReturnInputsV1;
use wholepact_chain::{
    ChainAdapter, ChainError, LightwalletSubmissionBackend, NetworkPolicy, SubmissionAuthority,
    SubmissionPermit, SubmissionPolicy, SubmissionReview, SystemSubmissionClock,
};
use wholepact_protocol::authorization::retention::transaction::submission_handoff::{
    LocalSubmissionDispatch, LocalSubmissionHandoff, SubmissionHandoffConsent,
    SubmissionHandoffScope,
};
use wholepact_signer::authority_bridge::{
    born_dispatch_ipc::{
        BornDispatchRequestV1, BornSignerDispatchAdmissionV1, BornSubmissionRouteV1,
    },
    dispatch_ipc::BackendDisclosure,
    ipc::OriginalHistoryClient,
};

impl RetainedBornMergedTransactionV1<'_, '_, '_> {
    /// The caller MUST invoke this inside with_born_post_return_inputs_v1. No
    /// future or authority escapes that all-wallet DB-held callback.
    pub(in crate::host) fn dispatch_born_current_v1(
        &self,
        inputs: &HeldBornPostReturnInputsV1<'_>,
        clients: &[OriginalHistoryClient],
    ) -> Result<wholepact_chain::SubmissionDispatchReport> {
        // Held observations are usable only for this exact original merged
        // predecessor, not another transaction at an equal provider/tip.
        inputs.require_original_submission(self)?;
        let original_deadline = inputs.monotonic_deadline();
        self.check_current_until(original_deadline)?;
        inputs.check_current()?;
        if clients.len() != self.returns.len() {
            return Err(Error::Authentication);
        }
        let source = inputs.context().source();
        let adapter = ChainAdapter::testnet(
            &source.source_id,
            &source.endpoint,
            NetworkPolicy::default(),
        )?;
        if adapter.identity() != source
            || &adapter.public_read_profile_v1() != inputs.read_profile()
        {
            return Err(Error::Authentication);
        }
        let original_margin = self
            .original()
            .claim()
            .consumed
            .first()
            .ok_or(Error::Authentication)?
            .request
            .plan
            .common_context
            .read_profile
            .minimum_expiry_margin_blocks;
        let policy = SubmissionPolicy {
            minimum_expiry_margin_blocks: original_margin
                .max(SubmissionPolicy::default().minimum_expiry_margin_blocks),
            ..SubmissionPolicy::default()
        };
        let mut journal = self
            .host
            .submission
            .try_lock()
            .map_err(|_| Error::Permission)?;
        let descriptor = self.verified.descriptor();
        let backend: BackendDisclosure = serde_json::from_value(serde_json::json!({
            "schema_version":1,"profile_id":self.host.secrets.profile(),"principal_id":self.context.principal_id,
            "agreement_id":self.original().proposal().manifest().agreement.agreement_id,
            "submission_journal_identity":journal.identity(),"descriptor":descriptor,"backend":adapter.identity(),
            "purpose":"submit_exact_retained_transaction","confidence":"single_tls_provider_report_not_consensus",
            "minimum_expiry_margin_blocks":policy.minimum_expiry_margin_blocks,
        }))?;
        let requests = self
            .returns
            .iter()
            .map(|r| {
                let admission = r.admission();
                let terms = &admission.request.reservation.intent.terms;
                let operation = wholepact_core::proposal::canonical_digest(
                    "wholepact:born-dispatch-account-attempt:v1",
                    &serde_json::json!([
                        descriptor.operation_id,
                        terms.authorization_id,
                        inputs.digest(),
                        inputs.observed_at_ms(),
                        inputs.expires_at_ms()
                    ]),
                )
                .map_err(|_| Error::Invalid)?;
                Ok(BornDispatchRequestV1 {
                    authorization_id: terms.authorization_id.clone(),
                    expected_original_ref: r.history.evidence().original_ref.clone(),
                    expected_born_origin_digest: r.history.evidence().born_origin_digest.clone(),
                    operation_id: format!("born-dispatch-v1-{operation}"),
                    backend: backend.clone(),
                    submission_route: BornSubmissionRouteV1::from_actual(
                        &adapter.public_read_profile_v1(),
                    )
                    .map_err(|_| Error::Authentication)?,
                    original_admission_digest: admission
                        .admission_digest()
                        .map_err(|_| Error::Authentication)?,
                    construction_link_digest: admission
                        .request
                        .construction_link
                        .digest()
                        .map_err(|_| Error::Authentication)?,
                    current_input_observation_digest: inputs.digest().into(),
                    observed_at_ms: inputs.observed_at_ms(),
                    observation_expires_at_ms: inputs.expires_at_ms(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let backend_digest = requests
            .first()
            .ok_or(Error::Invalid)?
            .backend_digest()
            .map_err(|_| Error::Authentication)?;
        self.check_current_until(original_deadline)?;
        inputs.check_current()?;
        let approval=self.host.terminal.approve_born_dispatch_until_v1(&backend_digest,&format!("Authorize copying ONLY this already retained exact complete signed transaction into the exact submission journal identified below, and ONE exact born post-return transaction dispatch attempt to this provider and actual network route. This is a separate native usable-transaction handoff approval, not merely private-read consent.\nBackend/transaction: {}\nActual route/profile: {}\nFresh held-wallet observation: {}\nObservation window: {}..{} ms\nThe provider receives COMPLETE signed transaction bytes and connection metadata and may retain/link them. The provider reports are not independent consensus or global unspentness. No spending key is sent. Every original signer separately reviews this exact final transaction/provider and invokes its unchanged original witness session; the Host never receives a writer session key. Same-byte retries require fresh native/current-input/signer approval, never a replacement transaction. Timeout, rejection, cancellation or late revocation can leave an admitted or dispatched outcome and MUST retain exposure. The full original inputs remain locked locally through the awaited dispatch and durable outcome. No payment/finality claim follows this action.",serde_json::to_string_pretty(&backend)?,serde_json::to_string_pretty(&adapter.public_read_profile_v1())?,inputs.digest(),inputs.observed_at_ms(),inputs.expires_at_ms()), original_deadline, || { self.check_current_until(original_deadline)?; inputs.check_current() })?;
        self.check_current_until(original_deadline)?;
        inputs.check_current()?;
        approval.check()?;
        let native_current = || -> Result<()> {
            inputs.require_original_submission(self)?;
            self.check_current_until(original_deadline)?;
            inputs.check_current()?;
            approval.check()
        };
        let mut admissions = Vec::with_capacity(clients.len());
        for (client, request) in clients.iter().zip(&requests) {
            self.check_current_until(original_deadline)?;
            inputs.check_current()?;
            approval.check()?;
            admissions.push(client.request_born_dispatch_checked_until(request, original_deadline, || native_current().map_err(|_| wholepact_signer::authority_bridge::BridgeError::Permission)).map_err(|_|Error::Receipt("born dispatch witness admission may exist; preserve the exact original attempt and journals".into()))?);
            self.check_current_until(original_deadline)?;
            inputs.check_current()?;
            approval.check()?;
        }
        let check = |review: &SubmissionReview<'_>| -> std::result::Result<(), ChainError> {
            let deny = || ChainError::SubmissionNotAuthorized;
            native_current().map_err(|_| deny())?;
            if review.descriptor != descriptor
                || review.journal_identity != backend.submission_journal_identity
                || review.backend != source
                || review.context.source() != source
                || review.context.tip() != inputs.context().tip()
                || review
                    .context
                    .tip()
                    .height
                    .checked_add(u64::from(policy.minimum_expiry_margin_blocks))
                    .is_none_or(|h| h > u64::from(descriptor.expiry_height))
            {
                return Err(deny());
            }
            review.context.check_fresh_at(review.now_unix_seconds)?;
            inputs.context().check_fresh_at(review.now_unix_seconds)?;
            check_admissions(self, inputs, &requests, &admissions).map_err(|_| deny())?;
            native_current().map_err(|_| deny())
        };
        let gate = DispatchRetention {
            original: self,
            inputs,
            approval: &approval,
            backend: &backend,
        };
        let financial = self.host.financial.as_ref().ok_or(Error::Locked)?;
        let checkpoint = self.original().checkpoint();
        let proposal = self.original().proposal();
        let limits = ProvingLimits {
            maximum_actions: self.original().claim().maximum_actions,
        };
        let clock = SystemSubmissionClock;
        let mut authority = BornAuthority {
            check: &check,
            used: false,
        };
        financial
            .signed
            .retain_transaction_for_submission(
                self.context.clone(),
                &self.signature_key,
                checkpoint.pczt_bytes(),
                checkpoint.policy(),
                &self.signatures,
                limits,
                &gate,
                &proposal.manifest().agreement.obligation_id,
                &proposal.input().proposal_id,
                &self.submission_operation_id,
                LocalSubmissionHandoff {
                    transactions: LocalTransactionCheckpoint {
                        journal: &financial.transactions,
                        consent: &gate,
                    },
                    submission_journal: &mut journal,
                    authority: &mut authority,
                    backend: adapter.identity(),
                    chain_context: inputs.context(),
                    clock: &clock,
                    policy,
                    consent: &gate,
                },
            )
            .map_err(|_| uncertain())?;
        native_current().map_err(|_| uncertain())?;
        let mut authority = BornAuthority {
            check: &check,
            used: false,
        };
        let mut backend = LightwalletSubmissionBackend::new(adapter);
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Storage)?;
        let outcome = executor.block_on(async {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(original_deadline),
                financial.signed.dispatch_retained_transaction(
                    self.context.clone(),
                    &self.signature_key,
                    checkpoint.pczt_bytes(),
                    checkpoint.policy(),
                    &self.signatures,
                    limits,
                    &gate,
                    &proposal.manifest().agreement.obligation_id,
                    &proposal.input().proposal_id,
                    &self.submission_operation_id,
                    LocalSubmissionDispatch {
                        transactions: LocalTransactionCheckpoint {
                            journal: &financial.transactions,
                            consent: &gate,
                        },
                        submission_journal: &mut journal,
                        authority: &mut authority,
                        backend: &mut backend,
                        clock: &clock,
                        policy,
                        consent: &gate,
                    },
                ),
            )
            .await
        });
        // Do not hold wallet locks while a cancelled resolver/runtime background
        // task winds down. The borrowed dispatch future is already completed or
        // dropped; any network effect remains uncertain in the original journal.
        executor.shutdown_timeout(std::time::Duration::ZERO);
        let report = outcome.map_err(|_| uncertain())?.map_err(|_| uncertain())?;
        // A late check cannot retract a durable attempt or provider effect.
        native_current().map_err(|_| uncertain())?;
        Ok(report)
    }
}
fn check_admissions(
    original: &RetainedBornMergedTransactionV1<'_, '_, '_>,
    inputs: &HeldBornPostReturnInputsV1<'_>,
    requests: &[BornDispatchRequestV1],
    admissions: &[BornSignerDispatchAdmissionV1<'_>],
) -> Result<()> {
    inputs.require_original_submission(original)?;
    if requests.len() != original.returns.len() || admissions.len() != requests.len() {
        return Err(Error::Authentication);
    }
    for ((old, request), actual) in original.returns.iter().zip(requests).zip(admissions) {
        actual
            .matches_request_until(request, inputs.monotonic_deadline())
            .map_err(|_| Error::Permission)?;
        let a = actual.descriptor();
        if &a.original != old.admission()
            || a.request.current_input_observation_digest != inputs.digest()
            || a.request.observed_at_ms != inputs.observed_at_ms()
            || a.request.observation_expires_at_ms != inputs.expires_at_ms()
            || a.request.dispatch.backend_disclosure_digest
                != request
                    .backend_digest()
                    .map_err(|_| Error::Authentication)?
        {
            return Err(Error::Authentication);
        }
    }
    original.check_current_until(inputs.monotonic_deadline())?;
    inputs.check_current()
}
type Check<'a> = dyn Fn(&SubmissionReview<'_>) -> std::result::Result<(), ChainError> + 'a;
struct BornAuthority<'a> {
    check: &'a Check<'a>,
    used: bool,
}
struct BornPermit<'a> {
    check: &'a Check<'a>,
}
impl<'a> SubmissionAuthority for BornAuthority<'a> {
    type Permit = BornPermit<'a>;
    fn authorize(
        &mut self,
        review: &SubmissionReview<'_>,
    ) -> std::result::Result<Self::Permit, ChainError> {
        if self.used {
            return Err(ChainError::SubmissionNotAuthorized);
        }
        (self.check)(review)?;
        self.used = true;
        Ok(BornPermit { check: self.check })
    }
}
impl SubmissionPermit for BornPermit<'_> {
    fn check_current(
        &mut self,
        review: &SubmissionReview<'_>,
    ) -> std::result::Result<(), ChainError> {
        (self.check)(review)
    }
}
struct DispatchRetention<'a, 'read, 'owner, 'host> {
    original: &'a RetainedBornMergedTransactionV1<'read, 'owner, 'host>,
    inputs: &'a HeldBornPostReturnInputsV1<'a>,
    approval: &'a crate::terminal::PublicationApproval,
    backend: &'a BackendDisclosure,
}
impl DispatchRetention<'_, '_, '_, '_> {
    fn current(&self) -> bool {
        self.inputs
            .require_original_submission(self.original)
            .is_ok()
            && self
                .original
                .check_current_until(self.inputs.monotonic_deadline())
                .is_ok()
            && self.inputs.check_current().is_ok()
            && self.approval.check().is_ok()
    }
}
impl SignedRetentionConsent for DispatchRetention<'_, '_, '_, '_> {
    fn permits(&self, s: &SignedRetentionScope) -> bool {
        self.current()
            && s.signature_set_digest == self.original.signed_scope.signature_set_digest
            && serde_json::to_vec(&s.context).ok()
                == serde_json::to_vec(&self.original.context).ok()
            && SignedRetentionConsent::permits(&self.original.native, s)
            && self.current()
    }
}
impl TransactionRetentionConsent for DispatchRetention<'_, '_, '_, '_> {
    fn permits(&self, s: &TransactionRetentionScope) -> bool {
        SignedRetentionConsent::permits(self, &s.signed_scope)
            && TransactionRetentionConsent::permits(&self.original.native, s)
            && self.current()
    }
}
impl SubmissionHandoffConsent for DispatchRetention<'_, '_, '_, '_> {
    fn permits(&self, s: &SubmissionHandoffScope<'_>) -> bool {
        TransactionRetentionConsent::permits(self, s.retained)
            && s.descriptor == self.original.verified.descriptor()
            && s.backend.source_id == self.backend.backend.source_id
            && s.backend.endpoint == self.backend.backend.endpoint
            && s.backend.trust_profile == self.backend.backend.trust_profile
            && s.destination_journal_identity == self.backend.submission_journal_identity
            && self.current()
    }
}
fn uncertain() -> Error {
    Error::Receipt("born submission retention or dispatch may have committed; preserve exact transaction/operation and reconcile existing journals, never clear exposure or replace".into())
}
