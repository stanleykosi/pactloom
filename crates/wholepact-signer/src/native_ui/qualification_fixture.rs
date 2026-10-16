//! Fixed public never-funded whole-flow qualification ONLY. This module is absent
//! unless synthetic-qualification + native-ui + authority-signing are all enabled.
//! It accepts no vault path, entropy, key, provider pin, permission flag or economic
//! terms. Native entry/clicks and the current-process provider pin are explicit
//! synthetic substitutions, never GUI, installer or process-attestation evidence.
use super::{
    authority::{ExactNativeReview, NativeAuthority},
    runtime::AuthenticatedPairing,
};
use crate::{
    account::{AccountVault, PendingAccount},
    authority_bridge::{
        self,
        disclosure::WitnessDisclosureReview,
        ipc::{HistoryRequest, OriginalHistoryClient},
        protocol::AuthorizationDeliveryScope,
        provider::InstalledSignerProvider,
    },
    consent_journal::*,
    files::PrivateDirectory,
    ipc::{LocalEvent, LocalIpc, PairScope},
    manifest::{LocalSelection, ReviewInputs},
    Error, Result,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use wholepact_core::*;
use wholepact_protocol::{
    construction::*,
    review::{encode_testnet_receiver, ReviewPolicy},
};
use wholepact_wallet::wallet::protected_sync::*;
use wholepact_wallet::{WalletKeyUseConfidence, WalletKeyUsePolicy};
#[path = "qualification/wallet_server.rs"]
mod wallet_server;
#[path = "qualification/witness.rs"]
mod witness;

pub const PROFILE: &str = "ironwood-testnet-nu7-candidate";
pub const AGREEMENT: &str = "fixed-native-never-funded-agreement";
pub const PURPOSE: &str = "Fixed never-funded concrete signer qualification";
pub const OPERATOR: &str = "fixed-native-synthetic-prover";
pub const RETENTION: &str = "Temporary private qualification journals only";
const AUTHORIZATION: &str = "fixed-native-authorization";

pub struct FixedAuthorityFixture {
    directory: tempfile::TempDir,
    ipc: Option<LocalIpc>,
    vault: AccountVault,
    journal: Arc<SignerConsentJournal>,
    authority: NativeAuthority,
    wallet: ProtectedWalletSync,
    _wallet_directory: tempfile::TempDir,
    wallet_server: tokio::task::JoinHandle<()>,
    selection: Option<ProtectedContribution>,
    manifest: ProposalManifest,
    context: ConstructionContext,
}
impl FixedAuthorityFixture {
    /// Only the fixed public mnemonic-derived account and fabricated local block.
    /// No file or network supplied by a caller can become an authority input.
    pub async fn new() -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("wholepact-fixed-native-never-funded-")
            .tempdir()?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        // Fail before proving if the actual kernel IPC source is unavailable.
        let (left, right) = std::os::unix::net::UnixStream::pair()?;
        crate::native_peer::PeerProcess::observe(&left)?;
        drop((left, right));
        // The production admission path requires a real filesystem listener.
        // Detect that requirement before account setup, scans or any expensive proof.
        let ipc = LocalIpc::bind(PrivateDirectory::create(&directory.path().join("ipc"))?)?;
        let pending = PendingAccount::fixed_never_funded_qualification(0)?;
        let words = pending.recovery_words()?;
        let verified = pending.verify_backup(&words)?;
        let mut vault = AccountVault::create(
            &directory.path().join("fixed-signer"),
            verified,
            b"PUBLIC-NEVER-FUNDED-QUALIFICATION-PASSWORD",
        )?;
        let journal = Arc::new(vault.create_authority_journal()?);
        // Synthetic source entry. No Wayland connection or human click is claimed.
        let authority = NativeAuthority::entered_native_window()?;
        let fvk = vault.account().fvk()?;
        let (_, endpoint, wallet_server, _) = wallet_server::fake_server(&fvk).await;
        let (wallet_directory, path, key) = wallet_server::database(&fvk);
        let mut wallet = wallet_server::controller(&path, &key, &endpoint);
        wallet
            .synchronize(&wallet_server::FixtureAccess(true), SyncLimits::default())
            .await
            .map_err(|_| Error::Verification)?;
        let selected = wallet
            .select_contribution(
                &wallet_server::FixtureAccess(true),
                &fvk,
                &vault.account_id()?,
                110_000,
                &[],
            )
            .map_err(|_| Error::Verification)?;
        let own = selected.selection();
        let receiver =
            encode_testnet_receiver(&fvk.address_at(0u32, orchard::keys::Scope::External));
        let manifest = ProposalManifest {
            agreement: AgreementDraft {
                schema_version: 1,
                agreement_id: AGREEMENT.into(),
                obligation_id: "fixed-native-never-funded-obligation".into(),
                revision: 1,
                purpose: PURPOSE.into(),
                organizer_identity: authority.principal_id().into(),
                network_profile_id: PROFILE.into(),
                recipients: vec![Recipient {
                    recipient_id: "fixed-recipient".into(),
                    address: receiver.clone(),
                    amount: amount(100_000),
                    memo: None,
                    instruction_provenance: "Public fixed synthetic recipient; never fund".into(),
                }],
                funding_policy: FundingPolicy::Exact {
                    target: amount(100_000),
                },
                fee_policy: FeePolicy::ProRata,
                privacy_profile: PrivacyProfile {
                    mode: PrivacyMode::DeclaredOperator,
                    proving_operator: Some(OPERATOR.into()),
                    dedicated_accounts_required: true,
                },
                coordination_deadline: None,
                confirmation_policy: ConfirmationPolicy::default(),
                extensions: vec![],
            },
            participants: vec![ParticipantAllocation {
                participant_id: "fixed-participant".into(),
                account_id: vault.account_id()?,
                contribution: amount(100_000),
                fee_share: amount(10_000),
                fee_cap: amount(10_000),
                maximum_net_debit: amount(110_000),
                charges: vec![],
            }],
            inputs: own
                .notes()
                .iter()
                .map(|n| ClaimedInput {
                    input_id: n.input_id.clone(),
                    participant_id: "fixed-participant".into(),
                    account_id: own.account_id().into(),
                    amount: amount(n.note.value().inner()),
                    ownership_evidence_ref: None,
                })
                .collect(),
            outputs: vec![
                ClaimedOutput {
                    output_id: "fixed-recipient-output".into(),
                    address: receiver,
                    amount: amount(100_000),
                    allocation: OutputAllocation::Recipient {
                        recipient_id: "fixed-recipient".into(),
                    },
                },
                ClaimedOutput {
                    output_id: "fixed-change".into(),
                    address: encode_testnet_receiver(&own.change_address()),
                    amount: amount(90_000),
                    allocation: OutputAllocation::Return {
                        participant_id: "fixed-participant".into(),
                        account_id: own.account_id().into(),
                        ownership_evidence_ref: None,
                    },
                },
            ],
            transaction_fee: amount(10_000),
            expiry_height: 4_465_070,
        };
        let context = ConstructionContext {
            anchor: own.context().anchor_root,
            anchor_height: own.context().anchor_height,
            anchor_block_hash: own.context().anchor_hash_protocol,
            target_height: own.context().tip_height + 1,
        };
        Ok(Self {
            directory,
            ipc: Some(ipc),
            vault,
            journal,
            authority,
            wallet,
            _wallet_directory: wallet_directory,
            wallet_server,
            selection: Some(selected),
            manifest,
            context,
        })
    }
    pub fn manifest(&self) -> &ProposalManifest {
        &self.manifest
    }
    pub fn principal_id(&self) -> &str {
        self.authority.principal_id()
    }
    pub fn construction_context(&self) -> ConstructionContext {
        self.context
    }
    pub fn take_contribution(&mut self) -> Result<Vec<OwnedContribution>> {
        let selected = self.selection.take().ok_or(Error::ReviewMismatch)?;
        // Dropping the live selection guard does not grant key use: signing later
        // requires a fresh authenticated ticket under the real wallet writer lock.
        Ok(vec![
            selected
                .into_current_contribution()
                .map_err(|_| Error::Verification)?
                .0,
        ])
    }
    /// Match the full generated fixture manifest before entering any approval path.
    /// Ordinary caller-selected accounts/outputs/fees/inputs are never admitted.
    pub async fn with_signed_result<R>(
        &mut self,
        proposal: &Proposal,
        proved: &[u8],
        policy: &ReviewPolicy,
        operation: impl FnOnce(&FixedSignedFlow<'_>) -> R,
    ) -> Result<R> {
        if proposal.manifest() != &self.manifest || proposal.input().previous_proposal_id.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        let mut ipc = self.ipc.take().ok_or(Error::ReviewMismatch)?;
        let scope = PairScope {
            account_id: self.vault.account_id()?,
            agreement_id: AGREEMENT.into(),
            participant_id: "fixed-participant".into(),
            manifest_digest: proposal.manifest_digest().into(),
            history_read: true,
            authorization_export: true,
            preconstruction_export: false,
        };
        let client = thread::scope(|threads| -> Result<OriginalHistoryClient> {
            let path = ipc.socket_path().to_owned();
            let worker = threads.spawn(move || {
                OriginalHistoryClient::pair(
                    InstalledSignerProvider::qualification_current_process().unwrap(),
                    &path,
                    "Fixed never-funded test controller",
                    scope,
                )
            });
            let event = next_event(&ipc)?;
            let LocalEvent::Pairing(pending) = event else {
                return Err(Error::Authentication);
            };
            let digest = pending.review_digest(ipc.generation())?;
            ipc.approve_pairing(
                pending,
                decision(&self.authority, &digest)?,
                &self.authority,
            )?;
            worker.join().unwrap().map_err(|_| Error::Authentication)
        })?;
        // A distinct actual token-proving request establishes the local association.
        // The requested original is deliberately nonexistent and cannot be returned.
        let pairing = thread::scope(|threads| -> Result<AuthenticatedPairing> {
            let dummy = HistoryRequest {
                authorization_id: "fixed-bootstrap-missing".into(),
                expected_original_consent_ref: "00".repeat(32),
                expected_enrollment_ref: "00".repeat(32),
                expected_manifest_ref: "00".repeat(32),
            };
            let borrowing_client = &client;
            let worker = threads.spawn(move || {
                assert!(borrowing_client.acquire(&dummy).is_err());
            });
            let LocalEvent::History { peer, stream, .. } = next_event(&ipc)? else {
                return Err(Error::Authentication);
            };
            drop(stream);
            worker.join().unwrap();
            AuthenticatedPairing::from_authenticated_request(peer)
        })?;
        let session = Arc::new(SignerConsentSession::from_trusted_launch(
            TrustedSignerLaunch::from_native(
                &self.authority,
                &self.journal,
                self.vault.account(),
                &pairing,
            )?,
        )?);
        let prepared = session.prepare_enrollment(
            self.vault.account(),
            proposal,
            AuthenticatedTransportIdentity::from_native(&pairing)?,
            EnrollmentRequest {
                participant_id: "fixed-participant".into(),
                aggregate_budget_limit_zatoshis: 110_000,
            },
        )?;
        let approved_decision =
            session.native_decision(decision(&self.authority, prepared.review_digest())?)?;
        let enrollment = self
            .journal
            .record_enrollment(session.approve_enrollment(prepared, approved_decision)?)?;
        let prepared = session.prepare_manifest(&enrollment, proposal)?;
        let approved_decision =
            session.native_decision(decision(&self.authority, prepared.review_digest())?)?;
        let manifest = self
            .journal
            .record_accepted_manifest(session.approve_manifest(prepared, approved_decision)?)?;
        let recipient_scope = wholepact_core::proposal::canonical_digest(
            "wholepact:signer-exact-authorization-recipient:v1",
            &(
                enrollment.transport(),
                AuthorizationDeliveryScope {
                    candidate_id: proposal.input().proposal_id.clone(),
                },
            ),
        )
        .map_err(|_| Error::Verification)?;
        let witness = witness::Witness::start(
            &self.directory.path().join("witness"),
            &self.vault.account_id()?,
            enrollment.reference(),
            &recipient_scope,
        );
        witness.activate();
        // Proving may outlive the old observation. Re-scan the unchanged fabricated
        // block through the real provider and select exactly the same original note.
        let fvk = self.vault.account().fvk()?;
        self.wallet
            .synchronize(&wallet_server::FixtureAccess(true), SyncLimits::default())
            .await
            .map_err(|_| Error::Verification)?;
        let selected = self
            .wallet
            .select_contribution(
                &wallet_server::FixtureAccess(true),
                &fvk,
                &self.vault.account_id()?,
                110_000,
                &[],
            )
            .map_err(|_| Error::Verification)?;
        let ticket = selected.key_use_ticket();
        let wallet_policy = WalletKeyUsePolicy {
            confidence: WalletKeyUseConfidence::SyntheticNeverChainEvidence,
            source_id: ticket.observation().source().source_id.clone(),
            endpoint: ticket.observation().source().endpoint.clone(),
            maximum_observation_age_seconds: 60,
            minimum_confirmations: 1,
            minimum_expiry_margin_blocks: 3,
        };
        let inputs = review_inputs(
            proposal,
            policy,
            self.context,
            LocalSelection::from_key_use_ticket(&ticket, &wallet_policy)?,
        )?;
        let prepared = session.prepare_spend(
            &enrollment,
            &manifest,
            self.vault.account(),
            proved,
            &inputs,
            AUTHORIZATION,
        )?;
        let expected_original = prepared.record().reference().to_owned();
        let head = witness
            .writer
            .snapshot()
            .map_err(|_| Error::Uncertain)?
            .head;
        let disclosure = WitnessDisclosureReview::new(&witness.writer, &prepared, head.clone())
            .map_err(|_| Error::Verification)?;
        let disclosure_decision = decision(&self.authority, disclosure.review_digest())?;
        let approved_disclosure = disclosure
            .approve(disclosure_decision, &self.authority)
            .map_err(|_| Error::ReviewMismatch)?;
        let spending =
            session.native_decision(decision(&self.authority, prepared.review_digest())?)?;
        let approval = session.approve_spend(prepared, spending)?;
        let pending = authority_bridge::prepare_authorization(
            &self.journal,
            &session,
            self.vault.account(),
            approval,
            proved,
            head,
            AuthorizationDeliveryScope {
                candidate_id: proposal.input().proposal_id.clone(),
            },
            approved_disclosure,
        )
        .map_err(|_| Error::Verification)?;
        let exact = pending.reservation().clone();
        let reserved = pending
            .reserve(&witness.writer)
            .map_err(|_| Error::Uncertain)?;
        let commit = reserved
            .authorize_with_wallet(&mut self.wallet, &ticket, &inputs)
            .map_err(|_| Error::Verification)?;
        assert_eq!(commit.original_consent_ref, expected_original);
        let before = witness.writer.snapshot().unwrap();
        let retry = authority_bridge::retry_original_reservation(
            &self.journal,
            &session,
            AUTHORIZATION,
            &witness.writer,
        )
        .unwrap();
        assert_eq!(
            retry.descriptor().request_digest,
            exact.request_digest().unwrap()
        );
        assert_eq!(
            witness.writer.snapshot().unwrap().outstanding_reservations,
            before.outstanding_reservations
        );
        assert_eq!(before.outstanding_debit_zatoshis, 110_000);
        // Reopen only the exact retained result. A new native session may inspect
        // originals, but cannot recreate the consumed old key-use continuation.
        session.invalidate()?;
        self.journal = Arc::new(self.vault.open_authority_journal()?);
        let session = Arc::new(SignerConsentSession::from_trusted_launch(
            TrustedSignerLaunch::from_native(
                &self.authority,
                &self.journal,
                self.vault.account(),
                &pairing,
            )?,
        )?);
        {
            let lease = self
                .journal
                .acquire_original_authorization(AUTHORIZATION, &session)?;
            assert!(lease.require_current_spending_decision().is_err());
            let retained = self.journal.bridge_result(&lease).unwrap();
            assert_eq!(retained.result_digest(), commit.result_digest);
            assert_eq!(retained.outbox_digest(), commit.outbox_digest);
        }
        witness.control(
            "fixed-owner-pause",
            wholepact_authority::OwnerControl::Pause,
        );
        assert_eq!(
            witness.owner.snapshot().unwrap().outstanding_debit_zatoshis,
            110_000
        );
        let history = HistoryRequest {
            authorization_id: AUTHORIZATION.into(),
            expected_original_consent_ref: expected_original,
            expected_enrollment_ref: enrollment.reference().into(),
            expected_manifest_ref: manifest.reference().into(),
        };
        let revoke = ipc.revocation();
        let revocation_check = ipc.revocation();
        let original_lease = self
            .journal
            .acquire_original_authorization(AUTHORIZATION, &session)?;
        let stopping = Arc::new(AtomicBool::new(false));
        let stop = stopping.clone();
        let journal = self.journal.clone();
        let session = session.clone();
        let worker = thread::spawn(move || {
            let mut readers = vec![];
            while !stop.load(Ordering::Acquire) {
                if let Some(event) = ipc.next_event() {
                    match event {
                        LocalEvent::History {
                            peer,
                            stream,
                            history,
                        } => {
                            let journal = journal.clone();
                            let session = session.clone();
                            readers.push(thread::spawn(move || {
                                authority_bridge::ipc::serve_original_history(
                                    stream, peer, history, &journal, &session,
                                )
                            }));
                        }
                        LocalEvent::Export {
                            peer,
                            stream,
                            history,
                        } => {
                            authority_bridge::ipc::serve_original_authorization_result(
                                stream, peer, history, &journal, &session,
                            )
                            .unwrap();
                        }
                        _ => panic!("unexpected fixed fixture event"),
                    }
                } else {
                    thread::sleep(Duration::from_millis(2));
                }
            }
            ipc.revoke_all();
            for reader in readers {
                let _ = reader.join().unwrap();
            }
        });
        let result = operation(&FixedSignedFlow {
            client: &client,
            history: &history,
            commit: &commit,
            revoke,
        });
        revocation_check.close();
        assert!(original_lease.check_current().is_err());
        drop(original_lease);
        stopping.store(true, Ordering::Release);
        worker.join().unwrap();
        Ok(result)
    }
}
impl Drop for FixedAuthorityFixture {
    fn drop(&mut self) {
        self.wallet_server.abort();
    }
}
/// Only the original fixed fixture's authenticated client and exact retained IDs.
/// No journal, key, approval constructor or arbitrary signing method is exposed.
pub struct FixedSignedFlow<'a> {
    pub client: &'a OriginalHistoryClient,
    pub history: &'a HistoryRequest,
    pub commit: &'a authority_bridge::AuthorizationCommit,
    revoke: crate::ipc::IpcRevocation,
}
impl FixedSignedFlow<'_> {
    pub fn revoke_fixture_pairing(&self) {
        self.revoke.close();
    }
}
fn amount(v: u64) -> Amount {
    Amount::from_zatoshis(v).unwrap()
}
fn decision(authority: &NativeAuthority, digest: &str) -> Result<super::NativeDecision> {
    let mut review = ExactNativeReview::stage(
        authority,
        digest,
        "EXPLICIT SYNTHETIC NEVER-FUNDED QUALIFICATION; no human input".into(),
        1,
    )?;
    assert!(review.continue_from_native_click(false, 1).is_err());
    review.continue_from_native_click(true, 1)?;
    review.consume_native_click(true, 1, &format!("AUTHORIZE {}", &digest[..12]))
}
fn next_event(ipc: &LocalIpc) -> Result<LocalEvent> {
    let start = Instant::now();
    loop {
        if let Some(event) = ipc.next_event() {
            return Ok(event);
        }
        if start.elapsed() > Duration::from_secs(5) {
            return Err(Error::Authentication);
        }
        thread::sleep(Duration::from_millis(2));
    }
}
fn review_inputs(
    proposal: &Proposal,
    policy: &ReviewPolicy,
    context: ConstructionContext,
    selection: LocalSelection,
) -> Result<ReviewInputs> {
    if policy.participants.len() != 1
        || policy.inputs.len() != 1
        || proposal.manifest().inputs.len() != 1
    {
        return Err(Error::Verification);
    }
    let input_actions = vec![InputActionMapping {
        input_id: proposal.manifest().inputs[0].input_id.clone(),
        account_id: proposal.manifest().inputs[0].account_id.clone(),
        action_index: policy.inputs[0].action_index,
    }];
    let output_actions = proposal
        .manifest()
        .outputs
        .iter()
        .map(|o| {
            let actual = policy
                .outputs
                .iter()
                .find(|p| {
                    p.value_zatoshis == o.amount.as_zatoshis()
                        && encode_testnet_receiver(&p.receiver) == o.address
                })
                .ok_or(Error::Verification)?;
            Ok(OutputActionMapping {
                output_id: o.output_id.clone(),
                action_index: actual.action_index,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ReviewInputs {
        construction_context: context,
        policy: policy.clone(),
        input_actions,
        output_actions,
        own_selection: selection,
    })
}
