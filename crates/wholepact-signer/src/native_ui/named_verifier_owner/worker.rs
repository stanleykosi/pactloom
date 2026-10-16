//! Private bounded worker owns all borrowing policy/key state. Only the actual
//! native UI can return a NativeDecision; prompts and status grant no authority.
use super::{
    NativeAuthorityBinding, NativeDecision, VerifierOwner,
    handoff::{ApprovedRequest, Lifetime, Phase},
};
use crate::{Error, Result};
use std::{
    sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
    thread::JoinHandle,
    time::{Duration, Instant},
};
use wholepact_offline_bridge::RetainedNamedVerifierOwner;
use wholepact_signer_origin::{
    NativeManualClient, named_verifier_policy::NamedVerifierPolicyScopeV1,
};
use zeroize::Zeroizing;

pub(super) struct AssertionInput {
    pub scopes: Vec<NamedVerifierPolicyScopeV1>,
    pub original: Zeroizing<Vec<u8>>,
    pub terms: wholepact_authority::offline::OfflineAuthorizationTerms,
    pub proposal: wholepact_core::Proposal,
    pub policy: super::request::PolicyClaims,
    pub input_actions: Vec<wholepact_protocol::construction::InputActionMapping>,
    pub output_actions: Vec<wholepact_protocol::construction::OutputActionMapping>,
    pub maximum_actions: usize,
}
pub(super) enum Notice {
    NeedOwner,
    PeerWait,
    Review {
        digest: String,
        display: Zeroizing<String>,
    },
    Finished(Result<String>),
}
enum Command {
    Owner(Box<VerifierOwner>),
    Decision(NativeDecision),
}
pub(super) struct Worker {
    pub notices: Receiver<Notice>,
    commands: Option<SyncSender<Command>>,
    join: Option<JoinHandle<()>>,
    pub lifetime: Lifetime,
    key: [u8; 32],
    profile_commitment: String,
}
impl Worker {
    pub fn start(approved: ApprovedRequest) -> Result<Self> {
        approved.lifetime.check()?;
        let lifetime = approved.lifetime.clone();
        let key = approved.key;
        let profile_commitment = approved.profile_commitment.clone();
        let (send_notice, notices) = mpsc::sync_channel(2);
        let (send_command, commands) = mpsc::sync_channel(1);
        let finished = lifetime.clone();
        let join = std::thread::spawn(move || {
            let result = run(approved, &send_notice, &commands);
            finished.set_phase(Phase::Finished);
            let _ = send_notice.try_send(Notice::Finished(result));
        });
        Ok(Self {
            notices,
            commands: Some(send_command),
            join: Some(join),
            lifetime,
            key,
            profile_commitment,
        })
    }
    pub fn key(&self) -> [u8; 32] {
        self.key
    }
    pub fn submit_owner(&self, owner: VerifierOwner) -> Result<()> {
        self.lifetime.check()?;
        owner.check_current()?;
        if owner.public_key() != self.key || owner.state_commitment()? != self.profile_commitment {
            return Err(Error::ReviewMismatch);
        }
        let phase = match self.lifetime.phase() {
            Phase::AwaitPossession => Phase::Possession,
            Phase::AwaitAssertion => Phase::Assertion,
            _ => return Err(Error::ReviewMismatch),
        };
        self.lifetime.set_phase(phase);
        self.commands
            .as_ref()
            .ok_or(Error::Locked)?
            .try_send(Command::Owner(Box::new(owner)))
            .map_err(|_| Error::Locked)
    }
    pub fn decide(&self, decision: NativeDecision) -> Result<()> {
        self.lifetime.check()?;
        self.commands
            .as_ref()
            .ok_or(Error::Locked)?
            .try_send(Command::Decision(decision))
            .map_err(|_| Error::Locked)
    }
    pub fn cancel(&mut self) {
        self.lifetime.cancel();
        self.commands.take();
    }
    pub fn reap(&mut self) {
        if self.join.as_ref().is_some_and(|j| j.is_finished()) {
            if let Some(j) = self.join.take() {
                let _ = j.join();
            }
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.cancel();
        self.reap();
    }
}
fn command(lifetime: &Lifetime, commands: &Receiver<Command>) -> Result<Command> {
    loop {
        lifetime.check()?;
        let remaining = lifetime
            .deadline()
            .checked_duration_since(Instant::now())
            .ok_or(Error::Locked)?;
        match commands.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(c) => {
                lifetime.check()?;
                return Ok(c);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Err(Error::Locked),
        }
    }
}
fn owner(
    approved: &ApprovedRequest,
    notices: &SyncSender<Notice>,
    commands: &Receiver<Command>,
    phase: Phase,
) -> Result<VerifierOwner> {
    approved.lifetime.set_phase(phase);
    notices
        .try_send(Notice::NeedOwner)
        .map_err(|_| Error::Locked)?;
    let Command::Owner(owner) = command(&approved.lifetime, commands)? else {
        return Err(Error::ReviewMismatch);
    };
    owner.check_current()?;
    if owner.public_key() != approved.key
        || owner.state_commitment()? != approved.profile_commitment
    {
        return Err(Error::ReviewMismatch);
    }
    Ok(*owner)
}
fn decision(
    source: &NativeAuthorityBinding,
    lifetime: &Lifetime,
    notices: &SyncSender<Notice>,
    commands: &Receiver<Command>,
    digest: &str,
    display: &str,
) -> Result<NativeDecision> {
    source.check_current()?;
    lifetime.check()?;
    notices
        .try_send(Notice::Review {
            digest: digest.into(),
            display: Zeroizing::new(display.into()),
        })
        .map_err(|_| Error::Locked)?;
    loop {
        source.check_current()?;
        lifetime.check()?;
        match commands.recv_timeout(Duration::from_millis(100)) {
            Ok(Command::Decision(value)) => {
                source.check_current()?;
                lifetime.check()?;
                if value.binding() != source || value.reviewed_digest() != digest {
                    return Err(Error::ReviewMismatch);
                }
                return Ok(value);
            }
            Ok(Command::Owner(_)) => return Err(Error::ReviewMismatch),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Err(Error::Locked),
        }
    }
}
fn run(
    approved: ApprovedRequest,
    notices: &SyncSender<Notice>,
    commands: &Receiver<Command>,
) -> Result<String> {
    let lifetime = &approved.lifetime;
    let deadline = lifetime.deadline();
    let endpoints = &approved.endpoints;
    let input = &approved.input;
    let mut clients = Vec::with_capacity(endpoints.len());
    for (endpoint, scope) in endpoints.iter().zip(&input.scopes) {
        lifetime.check()?;
        let proposal = scope.validate().map_err(|_| Error::InvalidData)?;
        let pair = wholepact_signer_origin::PairScope {
            account_id: scope.account_id.clone(),
            agreement_id: proposal.manifest().agreement.agreement_id.clone(),
            participant_id: scope.participant_id.clone(),
            manifest_digest: scope.pairing_digest().map_err(|_| Error::InvalidData)?,
            history_read: false,
            authorization_export: false,
            preconstruction_export: false,
        };
        let provider = wholepact_signer_origin::InstalledSignerProvider::load()
            .map_err(|_| Error::Unavailable)?;
        let client = NativeManualClient::begin_pair_before(
            provider,
            std::path::Path::new(endpoint),
            "Wholepact named verifier",
            pair,
            deadline,
        )
        .map_err(|_| Error::Locked)?
        .finish_checked(|| {
            lifetime
                .check()
                .map_err(|_| wholepact_signer_origin::Error::Permission)
        })
        .map_err(|_| Error::Locked)?;
        lifetime.check()?;
        clients.push(client);
    }
    let key_owner = owner(&approved, notices, commands, Phase::AwaitPossession)?;
    let mut requests = Vec::with_capacity(clients.len());
    for (client, scope) in clients.iter().zip(&input.scopes) {
        let source = key_owner.source.clone();
        let proof = key_owner.prepare_policy_proof(scope.clone(), client)?;
        let consent = decision(
            &source,
            lifetime,
            notices,
            commands,
            proof.digest(),
            proof.display(),
        )?;
        requests.push(proof.approve(consent)?);
    }
    // The actual signing key owner is destroyed before external peer focus is allowed.
    drop(key_owner);
    lifetime.set_phase(Phase::Collecting);
    notices
        .try_send(Notice::PeerWait)
        .map_err(|_| Error::Locked)?;
    let mut leases = Vec::with_capacity(clients.len());
    for (client, request) in clients.iter().zip(&requests) {
        lifetime.check()?;
        let lease = client
            .begin_named_verifier_policy_before(request, deadline)
            .map_err(|_| Error::Locked)?
            .finish_checked(|| {
                lifetime
                    .check()
                    .map_err(|_| wholepact_signer_origin::Error::Permission)
            })
            .map_err(|_| Error::Locked)?;
        leases.push(lease);
    }
    lifetime.check()?;
    let policy = input.policy.bind_current_leases(&leases)?;
    let retained = RetainedNamedVerifierOwner::from_current_policy_leases(
        &leases,
        wholepact_offline_bridge::NamedVerifierRetainedInputs {
            terms: input.terms.clone(),
            proposal: input.proposal.clone(),
            policy,
            input_actions: input.input_actions.clone(),
            output_actions: input.output_actions.clone(),
            maximum_actions: input.maximum_actions,
        },
        &approved.key,
    )
    .map_err(|_| Error::Verification)?;
    let prepared = retained
        .prepare(&input.original, &approved.key)
        .map_err(|_| Error::Verification)?;
    lifetime.check()?;
    let mut key_owner = owner(&approved, notices, commands, Phase::AwaitAssertion)?;
    let source = key_owner.source.clone();
    let pending = key_owner.stage(&prepared)?;
    let consent = decision(
        &source,
        lifetime,
        notices,
        commands,
        pending.digest(),
        pending.display(),
    )?;
    lifetime.check()?;
    let row = pending.approve(consent)?;
    drop(key_owner);
    for lease in leases {
        lease.finish().map_err(|_| Error::Uncertain)?;
    }
    Ok(row)
}
