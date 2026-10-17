//! One finite SAME-owner full payment continuation. Every authority-bearing
//! predecessor below comes from the actual constructor, native signer/witness,
//! installed IPC, retained proof/HPKE, wallet and submission owners. Only inert
//! exact protocol claims cross the finite worker. Synthetic acknowledgment and
//! fabricated receipt inclusion are explicitly not public-chain settlement.
//!
//! This is a synchronous synthetic PTY test driver, NOT a GUI event callback.
//! It deliberately waits for bounded native work and server teardown, including
//! on early errors. Moving Drop onto a worker does not make this driver
//! nonblocking and is not evidence of responsive attended GUI behavior.
#![cfg(all(test, feature = "synthetic-born-joined-qualification"))]

use super::full_joined_v3::FullProvedJoinedV1;
use super::joined_signer_worker_v1::{
    JoinedNamedCommandV1 as NamedCommand, JoinedNamedReplyV1 as NamedReply,
    JoinedSignerCommandV1 as Command, JoinedSignerReplyV1 as Reply, JoinedSignerWorkerV1,
};
use super::named_request_projection_v1::{disclose_original_request, original_request_claims};
use super::safe_diagnostics_v1::{self as diagnostic, Boundary as B};
use crate::{Error, Result, files};
use serde::Serialize;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use wholepact_authority::native_witness_owner::EphemeralHistoryServerV1;
use wholepact_signer::{
    authority_bridge::{BridgeError, born_history_ipc::BornOriginalHistoryRequestV1},
    native_ui::synthetic_born_joined_qualification::{
        OriginalNamedPaymentArtifactsV1, OriginalNamedReturnReferencesV1,
        OriginalNamedSetupMetadataV1,
    },
};
use wholepact_wallet::wallet::synthetic_born_payment_recipient_v1::SyntheticBornRecipientReceiptV1;
use zeroize::Zeroizing;

/// Only public finite-fixture outcome, constructed after actual exact-byte
/// dispatch and retained recipient decryption. Never an exposure-release token.
#[derive(Serialize)]
pub(super) struct FullSyntheticPaymentReceiptV1 {
    pub(super) exact_submission: wholepact_chain::SubmissionDispatchReport,
    pub(super) recipient: SyntheticBornRecipientReceiptV1,
    pub(super) public_network_settlement_verified: bool,
    pub(super) attended_native_acceptance_verified: bool,
}

struct ReturnedOriginalV1 {
    signer_index: usize,
    ciphertext_file: PathBuf,
    references: OriginalNamedReturnReferencesV1,
}

fn check(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(Error::Permission)
    } else {
        Ok(())
    }
}
fn worker_error(_: &'static str) -> Error {
    // The worker emits its closed safe boundary labels separately. Never copy
    // a private error/transcript/artifact into the foreground result.
    Error::Receipt(
        "synthetic same-owner named controller failed; exact original outcome must be retained"
            .into(),
    )
}
fn exchange(
    signers: &JoinedSignerWorkerV1,
    command: NamedCommand,
    deadline: Instant,
) -> Result<NamedReply> {
    check(deadline)?;
    signers
        .send(Command::Named(command))
        .map_err(worker_error)?;
    let answer = signers.receive_until(deadline).map_err(worker_error)?;
    check(deadline)?;
    match answer {
        Reply::Named(value) => Ok(value),
        _ => Err(Error::Authentication),
    }
}
fn require_done(reply: NamedReply, index: usize) -> Result<()> {
    match reply {
        NamedReply::Done { index: actual } if actual == index => Ok(()),
        _ => Err(Error::Authentication),
    }
}

impl FullProvedJoinedV1<'_> {
    /// Consumes the one-shot completed proof/carrier stage. This method cannot
    /// be called with a DTO, old constructor-only scenario or arbitrary backend.
    /// Any error ends this attempt; no new original, signature or send is made.
    pub(super) fn finish_original_payment(self) -> Result<FullSyntheticPaymentReceiptV1> {
        let Self {
            carried,
            witnesses,
            signers,
            born,
            payment_recipient,
            temporary_root,
            original_scenario_deadline,
        } = self;
        let host = carried.same_host();
        let owners = carried.owners();
        let clients = carried.original_clients();
        diagnostic::host(B::FullPaymentPredecessor, || {
            check(original_scenario_deadline)?;
            host.require_manual_session()?;
            if owners.len() != 2
                || clients.len() != 2
                || owners[0].profile().index() != 1
                || owners[1].profile().index() != 2
                || owners[0].profile().verifier_public_keys()
                    != owners[1].profile().verifier_public_keys()
                || host.require_financial_generation_admission().is_ok()
            {
                return Err(Error::Authentication);
            }
            for (owner, client) in owners.iter().zip(clients) {
                let index = owner.profile().index();
                let actual = born
                    .get(index)
                    .filter(|b| (1..=2).contains(&index) && b.index == index)
                    .ok_or(Error::Authentication)?;
                let carrier = owner.carrier()?;
                let scope = client.pairing_scope();
                if actual.account_id != owner.profile().account_id()
                    || actual.account_id != carrier.origin().account_id
                    || scope.account_id != actual.account_id
                    || scope.manifest_digest != carrier.origin().manifest_digest
                    || !scope.history_read
                    || scope.authorization_export
                    || scope.preconstruction_export
                {
                    return Err(Error::Authentication);
                }
                carrier.check_current()?;
            }
            Ok(())
        })?;
        // Each borrow is an actual retained immutable outbox row lent by the
        // same native original owner, not the exported ciphertext file itself.
        let retained = owners
            .iter()
            .map(|o| o.carrier()?.retained_export())
            .collect::<Result<Vec<_>>>()?;
        let original_deadline = retained
            .iter()
            .map(|v| v.deadline())
            .min()
            .ok_or(Error::Authentication)?
            .min(original_scenario_deadline);
        let mut metadata: Vec<OriginalNamedSetupMetadataV1> = Vec::with_capacity(2);
        // Real dedicated servers remain alive through final current/dispatch.
        // There are no shared listeners or subsequent account substitutions.
        let mut servers: Vec<EphemeralHistoryServerV1> = Vec::with_capacity(2);
        for (owner, actual) in owners.iter().zip(&retained) {
            check(original_deadline)?;
            actual.check_current()?;
            let index = owner.profile().index();
            let witness = witnesses.for_original(&born[index])?;
            let provenance = actual
                .origin()
                .require_historical_provenance_v2()
                .map_err(|_| Error::Authentication)?;
            let identity = provenance
                .source_identity_digest()
                .map_err(|_| Error::Authentication)?;
            let policy = provenance
                .source_policy_digest()
                .map_err(|_| Error::Authentication)?;
            let history_server = witness
                .serve_original_history()
                .map_err(|_| Error::Permission)?;
            let (signed_path, expected) = diagnostic::host(B::FullEnrollmentExport, || {
                match exchange(
                    signers,
                    NamedCommand::ExportEnrollment {
                        index,
                        source_identity: identity.clone(),
                        source_policy: policy.clone(),
                    },
                    original_deadline,
                )? {
                    NamedReply::Enrollment {
                        index: returned,
                        path,
                        enrollment,
                    } if returned == index => Ok((path, *enrollment)),
                    _ => Err(Error::Authentication),
                }
            })?;
            // The read-only server owns the namespace lock. Its concrete
            // finite worker is drained before any native namespace mutation.
            drain_history(history_server)?;
            if expected.policy.account_id != actual.origin().account_id
                || expected.policy.source_identity_digest != identity
                || expected.policy.source_policy_digest != policy
                || expected.policy.offline_signer_key_digest != actual.origin().signer_key_digest
                || expected.policy.return_recipient_key_digest
                    != actual.origin().host_return_key_digest
            {
                return Err(Error::Authentication);
            }
            let signed = Zeroizing::new(files::read_private(&signed_path, 1024 * 1024)?);
            let installed = diagnostic::host(B::FullEnrollmentInstall, || {
                check(original_deadline)?;
                witness
                    .review_original_born_offline_enrollment_v1(owner.witness_key(), &signed)
                    .map_err(|_| Error::Permission)
            })?;
            if installed != expected {
                return Err(Error::Authentication);
            }
            let artifacts = diagnostic::host(B::FullArtifactsInstall, || {
                check(original_deadline)?;
                witness
                    .install_original_born_artifacts_v1(
                        owner.witness_key(),
                        owner.profile().signer_public_key().as_bytes(),
                    )
                    .map_err(|_| Error::Permission)
            })?;
            servers.push(
                witness
                    .serve_original_born_offline_v1(owner.witness_key())
                    .map_err(|_| Error::Permission)?,
            );
            let setup = diagnostic::host(B::FullInstalledMetadata, || {
                match exchange(
                    signers,
                    NamedCommand::InstalledMetadata { index },
                    original_deadline,
                )? {
                    NamedReply::Metadata {
                        index: returned,
                        metadata,
                    } if returned == index => Ok(*metadata),
                    _ => Err(Error::Authentication),
                }
            })?;
            if setup.account_id != actual.origin().account_id
                || setup.profile_ref != owner.profile().profile_ref()
                || setup.signer_transport_public_key
                    != *owner.profile().signer_public_key().as_bytes()
                || setup.offline_policy != installed.policy
                || setup.enrollment_digest
                    != installed.digest().map_err(|_| Error::Authentication)?
                || setup.artifact_binding_digest
                    != artifacts
                        .binding
                        .digest()
                        .map_err(|_| Error::Authentication)?
            {
                return Err(Error::Authentication);
            }
            actual.check_current()?;
            metadata.push(setup);
        }
        if metadata.len() != 2 || servers.len() != 2 {
            return Err(Error::Authentication);
        }
        let verifier_key = owners[0].profile().verifier_public_keys().0;
        let mut returned = Vec::with_capacity(2);
        // Two DISTINCT selected-recipient assertions from the SAME verifier.
        // An authorization/package is never reused for the other account.
        for selected in 0..2 {
            let index = owners[selected].profile().index();
            let actual = &retained[selected];
            let claims = original_request_claims(
                host,
                [&retained[0], &retained[1]],
                [&metadata[0], &metadata[1]],
                verifier_key,
                selected,
                original_deadline,
            )?;
            let selected_scope = claims
                .scopes
                .iter()
                .find(|s| s.account_id == actual.origin().account_id)
                .ok_or(Error::Authentication)?
                .clone();
            let request_deadline = claims.original_deadline;
            let endpoints = match exchange(
                signers,
                NamedCommand::ArmVerifier {
                    selected_index: index,
                    scopes: Box::new(claims.scopes.clone()),
                    original_deadline: request_deadline,
                },
                request_deadline,
            )? {
                NamedReply::VerifierEndpoints(paths) => paths
                    .iter()
                    .map(|p| p.to_str().map(str::to_owned).ok_or(Error::Invalid))
                    .collect::<Result<Vec<_>>>()?,
                _ => return Err(Error::Authentication),
            };
            let disclosed = diagnostic::host(B::FullVerifierRequest, || {
                disclose_original_request(
                    host,
                    actual,
                    claims.terms,
                    &metadata[selected],
                    &claims.scopes,
                    &endpoints,
                )
            })?;
            match exchange(
                signers,
                NamedCommand::StartVerifier {
                    request: Zeroizing::new(disclosed.request_bytes().to_vec()),
                },
                request_deadline,
            )? {
                NamedReply::AssertionProgress(None) => {}
                _ => return Err(Error::Authentication),
            }
            let assertion = diagnostic::host(B::FullAssertion, || {
                let row = loop {
                    check(request_deadline)?;
                    actual.check_current()?;
                    match exchange(signers, NamedCommand::PollVerifier, request_deadline)? {
                        NamedReply::AssertionProgress(Some(row)) => break row,
                        NamedReply::AssertionProgress(None) => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        _ => return Err(Error::Authentication),
                    }
                };
                match exchange(
                    signers,
                    NamedCommand::ExportAssertion { index, row },
                    request_deadline,
                )? {
                    NamedReply::AssertionCiphertext {
                        index: returned,
                        bytes,
                    } if returned == index => Ok(bytes),
                    _ => Err(Error::Authentication),
                }
            })?;
            let authorization = disclosed.terms().authorization_id.clone();
            // Only exact maintained output bytes/claims are supplied. Signer
            // privately authenticates HPKE, history, source and its own policy,
            // derives its own receipt/origin and replaces only pending package
            // commitment with the actual authenticated NamedReviewBinding.
            let artifacts = OriginalNamedPaymentArtifactsV1 {
                terms: disclosed.terms().clone(),
                verifier_scope: selected_scope,
                expected_transformation_digest: disclosed.expected_transformation_digest().into(),
                own_context: disclosed.own_context_bytes().to_vec(),
                checkpoint_origin: actual.origin().clone(),
                checkpoint_plan: actual.export_plan().clone(),
                checkpoint_ciphertext: actual.ciphertext().to_vec(),
                assertion_ciphertext: assertion.to_vec(),
            };
            diagnostic::host(B::FullOriginalImport, || {
                match exchange(
                    signers,
                    NamedCommand::RetainPayment {
                        index,
                        artifacts: Box::new(artifacts),
                    },
                    request_deadline,
                )? {
                    NamedReply::OriginalRetained {
                        index: returned,
                        authorization: actual_authorization,
                        intent,
                    } if returned == index
                        && actual_authorization == authorization
                        && intent.is_absolute() =>
                    {
                        Ok(())
                    }
                    _ => Err(Error::Authentication),
                }
            })?;
            diagnostic::host(B::FullAdmission, || {
                require_done(
                    exchange(
                        signers,
                        NamedCommand::SubmitPayment { index },
                        original_deadline,
                    )?,
                    index,
                )
            })?;
            let result = diagnostic::host(B::FullSignatureReturn, || {
                match exchange(
                    signers,
                    NamedCommand::SignReturn { index },
                    original_deadline,
                )? {
                    NamedReply::OriginalReturn {
                        index: returned,
                        path,
                        references,
                    } if returned == index
                        && references.authorization_id == authorization
                        && path.is_absolute() =>
                    {
                        Ok(ReturnedOriginalV1 {
                            signer_index: index,
                            ciphertext_file: path,
                            references,
                        })
                    }
                    _ => Err(Error::Authentication),
                }
            })?;
            returned.push(result);
        }
        for result in &returned {
            require_done(
                exchange(
                    signers,
                    NamedCommand::BeginHostServing {
                        index: result.signer_index,
                    },
                    original_deadline,
                )?,
                result.signer_index,
            )?;
        }
        let mut histories = Vec::with_capacity(2);
        for ((client, result), actual) in clients.iter().zip(&returned).zip(&retained) {
            let request = BornOriginalHistoryRequestV1 {
                authorization_id: result.references.authorization_id.clone(),
                expected_original_ref: result.references.original_ref.clone(),
                expected_born_origin_digest: result.references.born_origin_digest.clone(),
            };
            histories.push(diagnostic::host(B::FullHistory, || {
                client
                    .acquire_born_original_history_checked_until(
                        &request,
                        original_deadline,
                        || {
                            check(original_deadline).map_err(|_| BridgeError::Permission)?;
                            host.require_manual_session()
                                .map_err(|_| BridgeError::Permission)?;
                            actual.check_current().map_err(|_| BridgeError::Permission)
                        },
                    )
                    .map_err(|_| Error::Permission)
            })?);
        }
        let mut returns = Vec::with_capacity(2);
        for ((actual, history), result) in retained.iter().zip(&histories).zip(&returned) {
            returns.push(diagnostic::host(B::FullReturnIntake, || {
                check(original_deadline)?;
                actual.check_current()?;
                let cipher = files::read_artifact(
                    &result.ciphertext_file,
                    wholepact_transport::MAX_FILE_BYTES,
                )?;
                host.retain_born_return_v1(actual, history, cipher)
            })?);
        }
        // One fresh ordinary identifier for this single exact submission. No
        // retry/new ID can be obtained from this consuming one-shot stage.
        let operation = format!(
            "synthetic-born-payment-{}",
            hex::encode(crate::random::<16>()?)
        );
        let merged = diagnostic::host(B::FullMerge, || {
            host.merge_born_returns_v1(&returns, &operation)
        })?;
        let (report, received) = diagnostic::host(B::FullCurrentDispatch, || {
            check(original_scenario_deadline)?;
            host.with_born_post_return_inputs_v1(&merged, |held| {
                // This callback is SYNCHRONOUS. All actual wallet transactions
                // stay held throughout native/IPC/witness/retention/send checks.
                let armed = carried.provider().arm_original_submission(&merged, held)?;
                let report = merged.dispatch_born_current_v1(held, clients)?;
                let received = armed.finish(&report)?;
                Ok((report, received))
            }).map_err(|_| Error::Receipt("synthetic exact dispatch may already be retained or received; preserve original journals, no retry or exposure release".into()))
        })?;
        let recipient = diagnostic::host(B::FullRecipientReceipt, || {
            check(original_scenario_deadline)?;
            let key = wholepact_storage_security::DatabaseKey::from_bytes(crate::random::<32>()?);
            let connection = wholepact_storage_security::create_encrypted(
                temporary_root.join("synthetic-original-payment-recipient.db"),
                &key,
            )
            .map_err(|_| Error::Storage)?;
            // This is after the all-wallet held callback, and uses the SAME
            // original recipient owner that supplied the agreement receiver.
            received.decrypt_recipient(payment_recipient, connection)
        })?;
        check(original_scenario_deadline)?;
        if recipient.public_network_inclusion_verified
            || recipient.independent_consensus_verified
            || report.clears_authorization_exposure
            || report.permits_replacement
            || carried.provider().denied_requests() != 0
        {
            return Err(Error::Authentication);
        }
        // Result values are public. Actual native/IPC/history owners remain in
        // scope until these checks finish and then drain before outer TempDir.
        Ok(FullSyntheticPaymentReceiptV1 {
            exact_submission: report,
            recipient,
            public_network_settlement_verified: false,
            attended_native_acceptance_verified: false,
        })
    }
}

fn drain_history(server: EphemeralHistoryServerV1) -> Result<()> {
    // Its existing Drop sets stop and joins bounded handlers. The synthetic
    // test driver intentionally waits here before namespace mutation. This is
    // blocking bounded teardown, NOT a production GUI event-handler strategy.
    // No server resumes; only the concrete original witness owner survives.
    std::thread::Builder::new()
        .name("synthetic-history-drain".into())
        .spawn(move || drop(server))
        .map_err(|_| Error::Permission)?
        .join()
        .map_err(|_| Error::Permission)
}
