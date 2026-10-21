//! Initial historical birth/roster setup for the separate durable fixture.
//! Actual Single anchor precedes two distinct born V2 roster publications. Every
//! native owner, signed export, witness extension and Host audit is produced by
//! its ordinary controller and durable consumer. No completed row is seeded.

#![cfg(all(test, feature = "synthetic-born-joined-qualification"))]
use super::safe_diagnostics_v1::{self as diagnostic, Boundary as B, Outcome};
use super::worker::{
    AGREEMENT_ID as AGREEMENT, JoinedSignerCommandV1 as Command, JoinedSignerPeerV1,
    JoinedSignerReplyV1 as Reply, JoinedSignerWorkerV1, OBLIGATION_ID as OBLIGATION,
    PARTICIPANT_IDS as PARTICIPANTS, PublicJoinedBornV1, RECIPIENT_ID, RECIPIENT_PROVENANCE,
};
use super::*;
fn mark(boundary: B) {
    diagnostic::emit(boundary, Outcome::Begin);
}
use crate::host::manual_enrollment::command::{
    joined_initial_v1::{PreparedJoinedInitialIntent, PreparedJoinedInitialPublication},
    roster_publication_v2::joined_host_v3::{
        JoinedRosterPreparationV3, PreparedJoinedRosterPublication,
    },
    roster_v2::joined_intent_v3::PreparedJoinedRosterIntent,
};
use wholepact_authority::native_witness_owner::EphemeralNativeWitnessV1;
use wholepact_signer_origin::manual_roster_v2::{
    HostManualRosterEnrollmentIntentV2, HostManualRosterPublicationRequestV2,
    ManualRosterPublicationAttemptV2,
};

/// These are the actual retained native source owners, not reconstructible receipts.
/// Fresh entries must reopen these same original encrypted sources. The field order drains the signer
/// worker before dropping witness/Host and removes the parent root last.
pub(super) struct DurableInitialV1 {
    pub(super) signers: JoinedSignerWorkerV1,
    pub(super) witness: EphemeralNativeWitnessV1,
    pub(super) host: Host,
    pub(super) born: [PublicJoinedBornV1; 3],
    pub(super) roster_intents: [HostManualRosterEnrollmentIntentV2; 2],
    pub(super) roster_requests: [HostManualRosterPublicationRequestV2; 2],
    /// Exact private exports remain owned by the same live signer worker.
    pub(super) roster_signed_extension_files: [std::path::PathBuf; 2],
    pub(super) roster_original_policy_files: [std::path::PathBuf; 2],
    pub(super) payment_receiver: String,
    pub(super) expiry_ms: u64,
    pub(super) temporary: tempfile::TempDir,
}
impl Drop for DurableInitialV1 {
    fn drop(&mut self) {
        // Session revocation is ordinary cancellation, not financial rollback.
        let _ = self.host.authority.fence.revoke();
    }
}

fn stage(error: &'static str) -> Error {
    // Worker errors are finite static labels only, never a private transcript.
    Error::Receipt(format!("synthetic joined controller stage failed: {error}"))
}
fn receive_peer(worker: &JoinedSignerWorkerV1) -> Result<JoinedSignerPeerV1> {
    match worker.receive().map_err(stage)? {
        Reply::Peer(peer) if Instant::now() < peer.deadline => Ok(peer),
        _ => Err(Error::Authentication),
    }
}
fn done(worker: &JoinedSignerWorkerV1, expected: usize) -> Result<()> {
    match worker.receive().map_err(stage)? {
        Reply::Done { index } if index == expected => Ok(()),
        _ => Err(Error::Authentication),
    }
}
fn selection(owner: &PublicJoinedBornV1, expiry_ms: u64) -> Result<Vec<u8>> {
    let participant = PARTICIPANTS.get(owner.index).ok_or(Error::Invalid)?;
    Ok(serde_json::to_vec(&serde_json::json!({
        "participant_id": participant,
        "privacy_domain": owner.privacy_domain,
        "recipient_scope_digests": [owner.recipient_scope_digest],
        "aggregate_budget_zatoshis": 1_000_000,
        "per_operation_limit_zatoshis": 400_000,
        "maximum_fee_share_zatoshis": 10_000,
        "maximum_transaction_fee_zatoshis": 20_000,
        "maximum_permit_lifetime_ms": 120_000,
        "expires_at_ms": expiry_ms,
    }))?)
}

/// Called only by the real controlling-PTY child. Returns the same actual owners
/// for fresh durable entry, not a fabricated account list.
pub(super) fn prepare(terminal: crate::terminal::Terminal) -> Result<DurableInitialV1> {
    let (temporary, host) = diagnostic::host(B::Bootstrap, || {
        crate::host::born_test_host_v1::create(terminal)
    })?;
    diagnostic::host(B::Session, || host.require_manual_session())?;
    mark(B::PaymentReceiver);
    let payment_receiver =
        wholepact_wallet::wallet::synthetic_born_receiver_blocks_v1::synthetic_payment_receiver_v1(
        );
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Invalid)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Invalid)?;
    let expiry_ms = now_ms.checked_add(3_600_000).ok_or(Error::Invalid)?;
    diagnostic::host(B::AgreementInput, || {
        create_agreement(&host, temporary.path(), &payment_receiver)
    })?;
    mark(B::WitnessSetup);
    let mut witness = EphemeralNativeWitnessV1::new().map_err(|error| { super::super::pristine_diagnostics_v1::source_authority_error(&error); stage("witness native setup") })?;
    mark(B::WitnessOrigin);
    let origin = witness
        .origin()
        .map_err(|error| { super::super::pristine_diagnostics_v1::source_authority_error(&error); stage("original witness pins") })?;
    mark(B::SignerStart);
    let signers =
        JoinedSignerWorkerV1::spawn(origin, payment_receiver.clone(), expiry_ms).map_err(stage)?;
    let mut born = Vec::with_capacity(3);
    for index in 0..3 {
        mark(B::BirthExport);
        signers.send(Command::ExportBirth(index)).map_err(stage)?;
        let (account_id, birth_digest, exported_file) = match signers.receive().map_err(stage)? {
            Reply::BirthExport {
                index: actual,
                account_id,
                birth_digest,
                exported_file,
            } if actual == index => (account_id, birth_digest, exported_file),
            _ => return Err(Error::Authentication),
        };
        mark(B::BirthRead);
        let bytes = zeroize::Zeroizing::new(crate::files::read_private(&exported_file, 131_072)?);
        mark(B::BirthEnroll);
        witness
            .enroll_signed_birth(&account_id, &bytes)
            .map_err(|error| { super::super::pristine_diagnostics_v1::source_authority_error(&error); stage("actual witness birth review") })?;
        mark(B::BirthHistory);
        let server = witness
            .serve_original_history()
            .map_err(|error| { super::super::pristine_diagnostics_v1::source_authority_error(&error); stage("original birth TLS server") })?;
        mark(B::BirthAcknowledge);
        signers.send(Command::Acknowledge(index)).map_err(stage)?;
        let acknowledged = match signers.receive().map_err(stage)? {
            Reply::Acknowledged(owner)
                if owner.index == index
                    && owner.account_id == account_id
                    && owner.birth_digest == birth_digest =>
            {
                owner
            }
            _ => return Err(Error::Authentication),
        };
        drop(server);
        born.push(acknowledged);
    }
    mark(B::BirthDistinct);
    let born: [PublicJoinedBornV1; 3] = born.try_into().map_err(|_| Error::Invalid)?;
    if born
        .iter()
        .enumerate()
        .any(|(i, a)| born[..i].iter().any(|b| a.account_id == b.account_id))
    {
        return Err(Error::Authentication);
    }
    publish_single_anchor(&host, &mut witness, &signers, &born[0], expiry_ms)?;
    let mut intents = Vec::with_capacity(2);
    let mut requests = Vec::with_capacity(2);
    let mut signed_extensions = Vec::with_capacity(2);
    let mut original_policies = Vec::with_capacity(2);
    for owner in &born[1..] {
        let (intent, request, signed_extension, original_policy) =
            publish_roster_member(&host, &mut witness, &signers, owner, expiry_ms)?;
        intents.push(intent);
        requests.push(request);
        signed_extensions.push(signed_extension);
        original_policies.push(original_policy);
    }
    // Read back the actual immutable Store roster through the genuine Engine
    // metadata owner. Success of a signer UI alone is not Host publication.
    mark(B::MetadataCheck);
    {
        let target = host
            .engine
            .manual_roster_intent_target(host.access()?, AGREEMENT)?;
        let members = target.members(host.access()?)?;
        if members.len() != 3
            || target.binding().roster_sequence != 4
            || born.iter().any(|owner| {
                !members.iter().any(|member| {
                    member.identity.account_id == owner.account_id
                        && member.identity.full_viewing_key_digest == owner.full_viewing_key_digest
                        && member.scope.participant_id == owner.participant_id
                        && member.scope.privacy_domain == owner.privacy_domain
                })
            })
        {
            return Err(Error::Authentication);
        }
        target.check_current(host.access()?)?;
    }
    // First publication is audit-only. It must not silently activate a generic
    // financial gate or create spendable/candidate inputs.
    mark(B::FinancialRefusal);
    if host.require_financial_generation_admission().is_ok() {
        return Err(Error::Authentication);
    }
    Ok(DurableInitialV1 {
        signers,
        witness,
        host,
        born,
        roster_intents: intents.try_into().map_err(|_| Error::Invalid)?,
        roster_requests: requests.try_into().map_err(|_| Error::Invalid)?,
        roster_signed_extension_files: signed_extensions.try_into().map_err(|_| Error::Invalid)?,
        roster_original_policy_files: original_policies.try_into().map_err(|_| Error::Invalid)?,
        payment_receiver,
        expiry_ms,
        temporary,
    })
}

pub(super) fn create_agreement(host: &Host, root: &std::path::Path, receiver: &str) -> Result<()> {
    let draft = serde_json::json!({
        "schema_version": 1, "agreement_id": AGREEMENT, "obligation_id": OBLIGATION,
        "revision": 1, "purpose": "Synthetic temporary joined controller qualification. No network funds.",
        "organizer_identity": "synthetic-roster-host",
        "network_profile_id": wholepact_protocol::construction::PROFILE_ID,
        "recipients": [{"recipient_id":RECIPIENT_ID, "address":receiver,
            "amount":"300000", "memo":null,
            "instruction_provenance":RECIPIENT_PROVENANCE}],
        "funding_policy":{"kind":"exact", "target":"300000"},
        "fee_policy":{"kind":"pro_rata"},
        "privacy_profile":{"mode":"declared_operator", "proving_operator":"synthetic-local-host", "dedicated_accounts_required":true},
        "coordination_deadline":null, "confirmation_policy":{"required_confirmations":10}, "extensions":[]
    });
    let path = root.join("synthetic-joined-agreement.json");
    crate::files::write_new(&path, &serde_json::to_vec(&draft)?)?;
    host.terminal
        .message(&format!("SYNTHETIC_JOINED_DRAFT_PATH={}\n", path.display()))?;
    diagnostic::host(B::AgreementNative, || host.create())
}

pub(super) fn publish_single_anchor(
    host: &Host,
    witness: &mut EphemeralNativeWitnessV1,
    signers: &JoinedSignerWorkerV1,
    owner: &PublicJoinedBornV1,
    expiry_ms: u64,
) -> Result<()> {
    mark(B::SinglePrepare);
    let prepared = PreparedJoinedInitialIntent::prepare(
        host,
        AGREEMENT,
        "synthetic-first-anchor-intent-v1".into(),
        owner.account_id.clone(),
        &selection(owner, expiry_ms)?,
    )?;
    mark(B::SingleOpen);
    signers
        .send(Command::OpenSingleIntent(
            owner.index,
            prepared.intent().clone(),
        ))
        .map_err(stage)?;
    let peer = receive_peer(signers)?;
    mark(B::SinglePair);
    let pending = prepared.begin_pair(peer.provider, &peer.endpoint)?;
    signers
        .send(Command::PollAndExportSingle(owner.index))
        .map_err(stage)?;
    mark(B::SingleSubmit);
    let client = pending.submit()?;
    mark(B::SingleExport);
    let (exported_file, request) = match signers.receive().map_err(stage)? {
        Reply::SingleExport {
            index,
            signed_extension_file,
            enrollment_request,
        } if index == owner.index => (signed_extension_file, enrollment_request),
        _ => return Err(Error::Authentication),
    };
    drop(client);
    let bytes = zeroize::Zeroizing::new(crate::files::read_private(&exported_file, 131_072)?);
    mark(B::SingleWitness);
    let extension = witness
        .review_original_single_extension_v1(&owner.account_id, &bytes)
        .map_err(|error| { super::super::pristine_diagnostics_v1::source_authority_error(&error); stage("actual Single extension review") })?;
    if extension.terms != request.terms {
        return Err(Error::Authentication);
    }
    mark(B::SinglePublicationPrepare);
    let prepared = PreparedJoinedInitialPublication::prepare(
        host,
        extension.clone(),
        "synthetic-first-anchor-audit-v1",
    )?;
    if prepared.request() != &request {
        return Err(Error::Authentication);
    }
    mark(B::SingleHistory);
    let server = witness
        .serve_original_single_attempt_v1(
            &owner.account_id,
            &extension.digest().map_err(|_| Error::Invalid)?,
        )
        .map_err(|error| { super::super::pristine_diagnostics_v1::source_authority_error(&error); stage("original Single attempt TLS server") })?;
    mark(B::SinglePublicationOpen);
    signers
        .send(Command::OpenSinglePublication(owner.index, request))
        .map_err(stage)?;
    let peer = receive_peer(signers)?;
    mark(B::SinglePublicationPair);
    let pending = prepared.begin_pair(peer.provider, &peer.endpoint)?;
    signers
        .send(Command::PollSinglePublication(owner.index))
        .map_err(stage)?;
    mark(B::SingleFinish);
    let _actual_audit = pending.finish()?;
    done(signers, owner.index)?;
    mark(B::SingleClose);
    signers
        .send(Command::CloseSinglePublication(owner.index))
        .map_err(stage)?;
    done(signers, owner.index)?;
    drop(server);
    Ok(())
}

pub(super) fn publish_roster_member(
    host: &Host,
    witness: &mut EphemeralNativeWitnessV1,
    signers: &JoinedSignerWorkerV1,
    owner: &PublicJoinedBornV1,
    expiry_ms: u64,
) -> Result<(
    HostManualRosterEnrollmentIntentV2,
    HostManualRosterPublicationRequestV2,
    std::path::PathBuf,
    std::path::PathBuf,
)> {
    mark(B::RosterPrepare);
    let prepared = PreparedJoinedRosterIntent::prepare(
        host,
        AGREEMENT,
        format!("synthetic-roster-intent-v2-{}", owner.index),
        owner.account_id.clone(),
        &selection(owner, expiry_ms)?,
    )?;
    let intent = prepared.intent().clone();
    mark(B::RosterOpen);
    signers
        .send(Command::OpenRosterIntent(owner.index, intent.clone()))
        .map_err(stage)?;
    let peer = receive_peer(signers)?;
    mark(B::RosterPair);
    let pending = prepared.begin_pair(peer.provider, &peer.endpoint)?;
    signers
        .send(Command::PollAndExportRoster(owner.index))
        .map_err(stage)?;
    mark(B::RosterSubmit);
    let client = pending.submit()?;
    mark(B::RosterExport);
    let (exported_file, original_policy_file, enrollment) =
        match signers.receive().map_err(stage)? {
            Reply::RosterExport {
                index,
                signed_extension_file,
                original_policy_file,
                enrollment_request,
            } if index == owner.index => (
                signed_extension_file,
                original_policy_file,
                enrollment_request,
            ),
            _ => return Err(Error::Authentication),
        };
    drop(client);
    let bytes = zeroize::Zeroizing::new(crate::files::read_private(&exported_file, 131_072)?);
    mark(B::RosterWitness);
    let original = witness
        .review_original_roster_extension_v2(&owner.account_id, &bytes)
        .map_err(|error| { super::super::pristine_diagnostics_v1::source_authority_error(&error); stage("actual roster extension review") })?;
    let request = HostManualRosterPublicationRequestV2 {
        version: 2,
        enrollment: enrollment.enrollment,
        roster: enrollment.roster,
        attempt: ManualRosterPublicationAttemptV2::InitialV2 {},
    };
    mark(B::RosterPublicationPrepare);
    let prepared = PreparedJoinedRosterPublication::prepare(
        host,
        request.clone(),
        original.extension.clone(),
        &format!("synthetic-roster-initial-audit-v2-{}", owner.index),
        false,
        JoinedRosterPreparationV3::AuditOnly,
    )?;
    mark(B::RosterHistory);
    let server = witness
        .serve_original_roster_attempt_v2(
            &owner.account_id,
            &original.extension.digest().map_err(|_| Error::Invalid)?,
            &original.attempt.attempt_digest,
        )
        .map_err(|error| { super::super::pristine_diagnostics_v1::source_authority_error(&error); stage("original roster attempt TLS server") })?;
    mark(B::RosterPublicationOpen);
    signers
        .send(Command::OpenRosterPublication(owner.index, request.clone()))
        .map_err(stage)?;
    let peer = receive_peer(signers)?;
    mark(B::RosterPublicationPair);
    let pending = prepared.begin_pair(peer.provider, &peer.endpoint)?;
    signers
        .send(Command::PollRosterPublication(owner.index))
        .map_err(stage)?;
    mark(B::RosterFinish);
    if pending.finish()?.is_some() {
        return Err(Error::Authentication);
    }
    done(signers, owner.index)?;
    mark(B::RosterClose);
    signers
        .send(Command::CloseRosterPublication(owner.index))
        .map_err(stage)?;
    done(signers, owner.index)?;
    drop(server);
    Ok((intent, request, exported_file, original_policy_file))
}

/// Exact finite PTY inputs. Approval delivery exercises the native controller;
/// it is deliberately labeled synthetic, never attended owner consent.
pub(super) fn inputs() -> Vec<Input<'static>> {
    let mut inputs = super::bootstrap_inputs();
    inputs.push(Input::CapturedPath {
        marker: "SYNTHETIC_JOINED_DRAFT_PATH=",
        prompt: "Native draft JSON file: ",
    });
    let review = |detail| Input::ExactReview {
        detail,
        approve: true,
    };
    inputs.push(review("Create NON-binding draft for principal"));
    for detail in [
        "Inspect complete protected ancestor identity coverage before requesting a new manual enrollment.",
        "SYNTHETIC JOINED TEST: disclose this actual Host-bound request-only first-account intent",
        "SYNTHETIC JOINED TEST: approve the exact bounded request-only pairing metadata",
        "SYNTHETIC JOINED TEST: request this actual first-account audit",
        "SYNTHETIC JOINED TEST: approve the finite original first-account pairing metadata",
        "Inspect the complete protected ancestor capsule for exact manual-enrollment distinctness.",
        "Retain one exact manual-enrollment AUDIT record",
    ] {
        inputs.push(review(detail));
    }
    for _ in 0..2 {
        for detail in [
            "Inspect complete protected ancestor identity coverage before requesting a new manual enrollment.",
            "SYNTHETIC JOINED TEST: disclose this actual Host-bound request-only additional-account intent",
            "SYNTHETIC JOINED TEST: approve the exact bounded request-only pairing metadata",
            "Inspect the complete protected ancestor capsule for exact manual-enrollment distinctness.",
            "Review the immutable original account owner for an exact additional-account roster AUDIT",
            "Retain this exact roster-bound audit under the original account ledger",
            "SYNTHETIC JOINED TEST: send ONLY this actual prepared roster request",
            "SYNTHETIC JOINED TEST: approve the exact bounded pairing metadata for this original roster publication",
        ] {
            inputs.push(review(detail));
        }
    }
    inputs
}

/// Original workspace prefix owns its Host in a move-safe slot for the mandatory vault cut.
pub(super) struct PrivateWorkspaceInitialV1 {
    pub(super) signers: JoinedSignerWorkerV1,
    pub(super) witness: EphemeralNativeWitnessV1,
    pub(super) host: Option<Host>,
    pub(super) born: [PublicJoinedBornV1; 3],
    pub(super) roster_intents: [HostManualRosterEnrollmentIntentV2; 2],
    pub(super) roster_requests: [HostManualRosterPublicationRequestV2; 2],
    /// Exact private exports remain owned by the same live signer worker.
    pub(super) roster_signed_extension_files: [std::path::PathBuf; 2],
    pub(super) roster_original_policy_files: [std::path::PathBuf; 2],
    pub(super) payment_receiver: String,
    pub(super) expiry_ms: u64,
    pub(super) temporary: tempfile::TempDir,
}
// Unlike the legacy fixture, this workspace-only owner permits moving the
// actual signer/witness out for explicit verified shutdown before process death.
// Host remains in its move-safe slot through the mandatory consuming vault cut.

pub(super) fn prepare_private_workspace_v1(terminal: crate::terminal::Terminal) -> Result<PrivateWorkspaceInitialV1> {
    prepare_private_workspace_with_profile_v1(terminal, PrivateWorkspaceProfileV1::FullExisting)
}

/// The same genuine three-account predecessor, stopped before viewing-wallet,
/// funding or fixed-candidate work, without an unused dispatcher credential.
pub(super) fn prepare_pristine_coordinator_v1(terminal: crate::terminal::Terminal) -> Result<PrivateWorkspaceInitialV1> {
    prepare_private_workspace_with_profile_v1(terminal, PrivateWorkspaceProfileV1::PristineCoordinator)
}

enum PrivateWorkspaceProfileV1 { FullExisting, PristineCoordinator }

fn prepare_private_workspace_with_profile_v1(
    terminal: crate::terminal::Terminal,
    profile: PrivateWorkspaceProfileV1,
) -> Result<PrivateWorkspaceInitialV1> {
    let (temporary, host) = diagnostic::host(B::PrivateWorkspaceBootstrap, || {
        crate::host::born_test_host_v1::create(terminal)
    })?;
    diagnostic::host(B::Session, || host.require_manual_session())?;
    mark(B::PaymentReceiver);
    let payment_receiver =
        wholepact_wallet::wallet::synthetic_born_receiver_blocks_v1::synthetic_payment_receiver_v1(
        );
    let now_ms: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Invalid)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Invalid)?;
    let expiry_ms = now_ms.checked_add(3_600_000).ok_or(Error::Invalid)?;
    diagnostic::host(B::AgreementInput, || {
        create_private_workspace_agreement_v1(&host, temporary.path(), &payment_receiver)
    })?;
    mark(B::WitnessSetup);
    let mut witness = match profile {
        PrivateWorkspaceProfileV1::FullExisting => EphemeralNativeWitnessV1::new(),
        PrivateWorkspaceProfileV1::PristineCoordinator => EphemeralNativeWitnessV1::new_for_pristine_delivery_review_v1(),
    }.map_err(|error| { super::super::pristine_diagnostics_v1::source_authority_error(&error); stage("witness native setup") })?;
    mark(B::WitnessOrigin);
    let origin = witness
        .origin()
        .map_err(|error| { super::super::pristine_diagnostics_v1::source_authority_error(&error); stage("original witness pins") })?;
    mark(B::SignerStart);
    let signers =
        JoinedSignerWorkerV1::spawn(origin, payment_receiver.clone(), expiry_ms).map_err(stage)?;
    let mut born = Vec::with_capacity(3);
    for index in 0..3 {
        mark(B::BirthExport);
        signers.send(Command::ExportBirth(index)).map_err(stage)?;
        let (account_id, birth_digest, exported_file) = match signers.receive().map_err(stage)? {
            Reply::BirthExport {
                index: actual,
                account_id,
                birth_digest,
                exported_file,
            } if actual == index => (account_id, birth_digest, exported_file),
            _ => return Err(Error::Authentication),
        };
        mark(B::BirthRead);
        let bytes = zeroize::Zeroizing::new(crate::files::read_private(&exported_file, 131_072)?);
        mark(B::BirthEnroll);
        witness
            .enroll_signed_birth(&account_id, &bytes)
            .map_err(|error| { super::super::pristine_diagnostics_v1::source_authority_error(&error); stage("actual witness birth review") })?;
        mark(B::BirthHistory);
        let server = witness
            .serve_original_history()
            .map_err(|error| { super::super::pristine_diagnostics_v1::source_authority_error(&error); stage("original birth TLS server") })?;
        mark(B::BirthAcknowledge);
        signers.send(Command::Acknowledge(index)).map_err(stage)?;
        let acknowledged = match signers.receive().map_err(stage)? {
            Reply::Acknowledged(owner)
                if owner.index == index
                    && owner.account_id == account_id
                    && owner.birth_digest == birth_digest =>
            {
                owner
            }
            _ => return Err(Error::Authentication),
        };
        drop(server);
        born.push(acknowledged);
    }
    mark(B::BirthDistinct);
    let born: [PublicJoinedBornV1; 3] = born.try_into().map_err(|_| Error::Invalid)?;
    if born
        .iter()
        .enumerate()
        .any(|(i, a)| born[..i].iter().any(|b| a.account_id == b.account_id))
    {
        return Err(Error::Authentication);
    }
    publish_single_anchor(&host, &mut witness, &signers, &born[0], expiry_ms)?;
    let mut intents = Vec::with_capacity(2);
    let mut requests = Vec::with_capacity(2);
    let mut signed_extensions = Vec::with_capacity(2);
    let mut original_policies = Vec::with_capacity(2);
    for owner in &born[1..] {
        let (intent, request, signed_extension, original_policy) =
            publish_roster_member(&host, &mut witness, &signers, owner, expiry_ms)?;
        intents.push(intent);
        requests.push(request);
        signed_extensions.push(signed_extension);
        original_policies.push(original_policy);
    }
    // Read back the actual immutable Store roster through the genuine Engine
    // metadata owner. Success of a signer UI alone is not Host publication.
    mark(B::MetadataCheck);
    {
        let target = host
            .engine
            .manual_roster_intent_target(host.access()?, AGREEMENT)?;
        let members = target.members(host.access()?)?;
        if members.len() != 3
            || target.binding().roster_sequence != 4
            || born.iter().any(|owner| {
                !members.iter().any(|member| {
                    member.identity.account_id == owner.account_id
                        && member.identity.full_viewing_key_digest == owner.full_viewing_key_digest
                        && member.scope.participant_id == owner.participant_id
                        && member.scope.privacy_domain == owner.privacy_domain
                })
            })
        {
            return Err(Error::Authentication);
        }
        target.check_current(host.access()?)?;
    }
    // First publication is audit-only. It must not silently activate a generic
    // financial gate or create spendable/candidate inputs.
    mark(B::FinancialRefusal);
    if host.require_financial_generation_admission().is_ok() {
        return Err(Error::Authentication);
    }
    Ok(PrivateWorkspaceInitialV1 {
        signers,
        witness,
        host: Some(host),
        born,
        roster_intents: intents.try_into().map_err(|_| Error::Invalid)?,
        roster_requests: requests.try_into().map_err(|_| Error::Invalid)?,
        roster_signed_extension_files: signed_extensions.try_into().map_err(|_| Error::Invalid)?,
        roster_original_policy_files: original_policies.try_into().map_err(|_| Error::Invalid)?,
        payment_receiver,
        expiry_ms,
        temporary,
    })
}

fn create_private_workspace_agreement_v1(host: &Host, root: &std::path::Path, receiver: &str) -> Result<()> {
    let principal = host.access()?.principal_id.clone();
    let draft = serde_json::json!({
        "schema_version": 1, "agreement_id": AGREEMENT, "obligation_id": OBLIGATION,
        "revision": 1, "purpose": "Synthetic temporary joined controller qualification. No network funds.",
        "organizer_identity": principal,
        "network_profile_id": wholepact_protocol::construction::PROFILE_ID,
        "recipients": [{"recipient_id":RECIPIENT_ID, "address":receiver,
            "amount":"300000", "memo":null,
            "instruction_provenance":RECIPIENT_PROVENANCE}],
        "funding_policy":{"kind":"exact", "target":"300000"},
        "fee_policy":{"kind":"pro_rata"},
        "privacy_profile":{"mode":"declared_operator", "proving_operator":principal, "dedicated_accounts_required":true},
        "coordination_deadline":null, "confirmation_policy":{"required_confirmations":10}, "extensions":[]
    });
    let path = root.join("synthetic-private-workspace-agreement.json");
    crate::files::write_new(&path, &serde_json::to_vec(&draft)?)?;
    host.terminal
        .message(&format!("SYNTHETIC_JOINED_DRAFT_PATH={}\n", path.display()))?;
    diagnostic::host(B::AgreementNative, || host.create())
}
