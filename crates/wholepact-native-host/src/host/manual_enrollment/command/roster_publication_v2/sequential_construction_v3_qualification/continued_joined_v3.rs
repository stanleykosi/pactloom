//! Concrete same-original continuation and retained-input consumer for the
//! temporary joined scenario. This leaf is not a native owner factory. All
//! private inputs and approvals still pass through the actual Host terminal.
#![cfg(all(test, feature = "synthetic-born-joined-qualification"))]

use super::joined_signer_worker_v1::{
    JoinedSignerCommandV1 as Command, JoinedSignerPeerV1, JoinedSignerReplyV1 as Reply,
    JoinedSignerWorkerV1, PublicJoinedBornV1,
};
use super::*;
use crate::host::financial::manual_roster_inventory_setup_v2::RetainedRosterCandidateInputsV2;
use crate::host::manual_enrollment::command::roster_publication_v2::{
    continuation_intent::joined_continuation_v3::PreparedJoinedRosterContinuationIntent,
    joined_host_v3::{JoinedRosterPreparationV3, PreparedJoinedRosterPublication},
};
use std::path::Path;
use wholepact_authority::{
    manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
    native_witness_owner::EphemeralNativeWitnessV1,
};
use wholepact_signer::native_ui::synthetic_born_joined_qualification::ExpectedRosterDisclosuresV1;
use wholepact_signer_origin::manual_roster_v2::{
    HostManualRosterEnrollmentIntentV2, HostManualRosterPublicationRequestV2,
    ManualRosterPublicationAttemptV2,
};

/// Inert evidence read back after actual independent native witness review.
/// The enclosing scenario must retain its original Host, signer and witness.
pub(super) struct ReviewedJoinedContinuationV3 {
    request: HostManualRosterPublicationRequestV2,
    extension: ManualRosterEnrollmentExtensionV2,
    signed_continuation_file: std::path::PathBuf,
}
impl ReviewedJoinedContinuationV3 {
    pub(super) fn request(&self) -> &HostManualRosterPublicationRequestV2 {
        &self.request
    }
    pub(super) fn signed_continuation_file(&self) -> &Path {
        &self.signed_continuation_file
    }
}

fn stage(label: &'static str) -> Error {
    Error::Receipt(format!(
        "synthetic continued controller stage failed: {label}"
    ))
}
fn peer(worker: &JoinedSignerWorkerV1) -> Result<JoinedSignerPeerV1> {
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
fn wall_ms() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Invalid)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Invalid)
}

/// Wait only for the actual immutable previous publication. No native request,
/// approval or new selection invocation exists across this wait. Clock changes
/// cannot extend the caller's already-captured monotonic scenario safety bound.
fn wait_previous_publication(deadline_ms: u64, scope_expiry_ms: u64, until: Instant) -> Result<()> {
    if deadline_ms >= scope_expiry_ms {
        return Err(Error::Permission);
    }
    loop {
        let now = wall_ms()?;
        let monotonic = Instant::now();
        if now >= scope_expiry_ms || monotonic >= until {
            return Err(Error::Permission);
        }
        if now >= deadline_ms {
            return Ok(());
        }
        std::thread::sleep(
            Duration::from_millis(deadline_ms - now)
                .min(Duration::from_millis(100))
                .min(until.saturating_duration_since(monotonic)),
        );
    }
}

/// The metadata arguments are exact original correlations, not authority.
/// Actual original association is rechecked by both independent native owners.
/// Arguments are split so retained contributions can borrow Host while the
/// scenario continues another original owner using its separate witness field.
pub(super) fn prepare_original_continuation(
    host: &Host,
    witness: &mut EphemeralNativeWitnessV1,
    signers: &JoinedSignerWorkerV1,
    owner: &PublicJoinedBornV1,
    original_intent: &HostManualRosterEnrollmentIntentV2,
    original_signed_extension_file: &Path,
    scenario_deadline: Instant,
) -> Result<ReviewedJoinedContinuationV3> {
    if !(1..=2).contains(&owner.index) {
        return Err(Error::Invalid);
    }
    host.require_manual_session()?;
    let prior = witness
        .observe_original_roster_attempt_v2(&owner.account_id)
        .map_err(|_| stage("actual prior roster observation"))?;
    original_intent
        .matches_terms(
            &prior.extension.account_extension.terms,
            &prior.extension.roster,
        )
        .map_err(|_| Error::Authentication)?;
    let previous_deadline = prior
        .attempt
        .last_publication_deadline_ms()
        .ok_or(Error::Authentication)?;
    wait_previous_publication(
        previous_deadline,
        prior.extension.account_extension.terms.scope.expires_at_ms,
        scenario_deadline,
    )?;
    host.require_manual_session()?;
    // Only a path to our actual private temporary export. The ordinary reader
    // still requests its own exact local-file disclosure approval below.
    host.terminal.message(&format!(
        "SYNTHETIC_JOINED_ORIGINAL_ROSTER_PATH={}\n",
        original_signed_extension_file.display(),
    ))?;
    let prepared = PreparedJoinedRosterContinuationIntent::prepare(host)?;
    if prepared.intent() != original_intent || Instant::now() >= scenario_deadline {
        return Err(Error::Authentication);
    }
    let history = witness
        .serve_original_roster_attempt_v2(
            &owner.account_id,
            &prior.extension.digest().map_err(|_| Error::Invalid)?,
            &prior.attempt.attempt_digest,
        )
        .map_err(|_| stage("original continuation history server"))?;
    signers
        .send(Command::OpenContinuationIntent(
            owner.index,
            prepared.intent().clone(),
        ))
        .map_err(stage)?;
    let peer = peer(signers)?;
    let pending = prepared.begin_pair(peer.provider, &peer.endpoint)?;
    signers
        .send(Command::PollAndExportContinuation(owner.index))
        .map_err(stage)?;
    let client = pending.submit()?;
    let signed_path = match signers.receive().map_err(stage)? {
        Reply::ContinuationExport {
            index,
            signed_continuation_file,
        } if index == owner.index => signed_continuation_file,
        _ => return Err(Error::Authentication),
    };
    drop(client);
    drop(history);
    let signed_bytes = zeroize::Zeroizing::new(crate::files::read_private(&signed_path, 131_072)?);
    let reviewed = witness
        .review_original_roster_continuation_v2(&owner.account_id, &signed_bytes)
        .map_err(|_| stage("independent exact continuation witness review"))?;
    if reviewed.extension != prior.extension
        || reviewed.attempt.sequence
            != prior
                .attempt
                .sequence
                .checked_add(1)
                .ok_or(Error::Invalid)?
        || reviewed.attempt.attempt_digest == prior.attempt.attempt_digest
        || Instant::now() >= scenario_deadline
    {
        return Err(Error::Authentication);
    }
    let request = HostManualRosterPublicationRequestV2 {
        version: 2,
        enrollment: wholepact_signer_origin::manual::HostManualEnrollmentRequest {
            terms: reviewed.extension.account_extension.terms.clone(),
        },
        roster: reviewed.extension.roster.clone(),
        attempt: ManualRosterPublicationAttemptV2::ContinuationV2 {
            continuation_digest: reviewed.attempt.attempt_digest,
            attempt_sequence: reviewed.attempt.sequence,
        },
    };
    Ok(ReviewedJoinedContinuationV3 {
        request,
        extension: reviewed.extension,
        signed_continuation_file: signed_path,
    })
}

/// Run the maintained native inventory/selection/retention path. The caller's
/// live multithread provider runtime must remain owned throughout this call.
/// No success is returned until the real Host durable consumer finishes.
pub(super) fn retain_continued_candidate<'host>(
    host: &'host Host,
    witness: &mut EphemeralNativeWitnessV1,
    signers: &JoinedSignerWorkerV1,
    owner: &PublicJoinedBornV1,
    reviewed: ReviewedJoinedContinuationV3,
    audit_key: &str,
) -> Result<RetainedRosterCandidateInputsV2<'host>> {
    let prepared = PreparedJoinedRosterPublication::prepare(
        host,
        reviewed.request.clone(),
        reviewed.extension.clone(),
        audit_key,
        true,
        JoinedRosterPreparationV3::CommonContextRetentionV2,
    )?;
    let (inventory, inventory_operation) =
        prepared.inventory_parts().ok_or(Error::Authentication)?;
    let (selection, selection_operation) =
        prepared.selection_parts().ok_or(Error::Authentication)?;
    selection
        .selection
        .require_original_retention_scope()
        .map_err(|_| Error::Authentication)?;
    let expected = ExpectedRosterDisclosuresV1 {
        inventory: inventory.clone(),
        inventory_operation: inventory_operation.into(),
        selection: selection.clone(),
        selection_operation: selection_operation.into(),
        retention_operation: prepared
            .retention_operation_id()
            .ok_or(Error::Authentication)?
            .into(),
    };
    let (attempt_digest, _) = match &reviewed.request.attempt {
        ManualRosterPublicationAttemptV2::ContinuationV2 {
            continuation_digest,
            attempt_sequence,
        } => (continuation_digest, attempt_sequence),
        _ => return Err(Error::Authentication),
    };
    let history = witness
        .serve_original_roster_attempt_v2(
            &owner.account_id,
            &reviewed.extension.digest().map_err(|_| Error::Invalid)?,
            attempt_digest,
        )
        .map_err(|_| stage("continued inventory original attempt server"))?;
    signers
        .send(Command::OpenContinuedPublication(
            owner.index,
            prepared.request().clone(),
            Some(expected),
        ))
        .map_err(stage)?;
    let peer = peer(signers)?;
    let pending = prepared.begin_pair(peer.provider, &peer.endpoint)?;
    signers
        .send(Command::PollContinuedPublicationAndDisclosures(owner.index))
        .map_err(stage)?;
    let retained = pending.finish()?.ok_or(Error::Authentication)?;
    done(signers, owner.index)?;
    signers
        .send(Command::CloseContinuedPublication(owner.index))
        .map_err(stage)?;
    done(signers, owner.index)?;
    drop(history);
    Ok(retained)
}
