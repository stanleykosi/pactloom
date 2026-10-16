//! Foreground-only composition for a genuine restored generation capsule.
//! Explicit CLI composition retains permanent financial denial in the Host.
//! Every admission is obtained anew; saved plans and audit records are not grants.
use super::layered::{PARENT_CAPSULE, PendingLayeredGeneration};
use crate::{Error, Result, generation_restore::RestoredGenerationCapsule, terminal::Terminal};
use serde::Serialize;
use std::path::Path;
use wholepact_signer::{
    authority_bridge::{ipc::OriginalHistoryClient, provider::InstalledSignerProvider},
    ipc::PairScope,
};
use wholepact_storage_security::{
    bundle::recovery::evidence::history::MAX_HISTORICAL_METADATA_BYTES,
    generation_archive::CopyScope,
};
use zeroize::Zeroizing;

use super::v3_routing::{require_available, signer_requests};

/// Bound both private serialized metadata and its terminal-escaped form. Leave
/// room for Terminal::confirm's fixed challenge and instructions. No scope,
/// account set or private witness descriptor is sent to stdout or a log.
fn review<T: Serialize>(description: &str, scope: &T) -> Result<Zeroizing<String>> {
    let encoded = super::encode(scope)?;
    let json = std::str::from_utf8(&encoded).map_err(|_| Error::Invalid)?;
    let mut detail = Zeroizing::new(String::new());
    let max = MAX_HISTORICAL_METADATA_BYTES
        .checked_sub(512)
        .ok_or(Error::Invalid)?;
    if description
        .len()
        .checked_add(json.len())
        .and_then(|n| n.checked_add(1))
        .is_none_or(|n| n > max)
    {
        return Err(Error::Invalid);
    }
    detail.push_str(description);
    detail.push('\n');
    detail.push_str(json);
    let rendered = detail
        .chars()
        .try_fold(0usize, |bytes, c| {
            bytes.checked_add(if c == '\n' || c == ' ' || c.is_ascii_graphic() {
                1
            } else {
                c.escape_default().count()
            })
        })
        .ok_or(Error::Invalid)?;
    if rendered > max {
        return Err(Error::Invalid);
    }
    Ok(detail)
}

/// This is the only source-opening path in this composition. RestoredGeneration-
/// Capsule authenticates the permanent quarantine, exact complete graph, private
/// key matrix and archived-snapshot account set before any target is created.
pub(crate) fn activate(
    terminal: Terminal,
    restored: &Path,
    successor: &Path,
    resume: bool,
) -> Result<()> {
    require_available()?;
    crate::files::validate_absolute(restored)?;
    crate::files::validate_absolute(successor)?;
    let initial = review(
        "READ HISTORICAL PRIVATE DATA from this permanently quarantined generation capsule. Authenticate every original and current host-owned record, viewing/scan data, witness, retained signature, exact transaction, transport history and NON-signing recovery key, including the complete inherited graph and registered financial dependencies. Saved signer admissions, old credentials, grants and financial confidence remain inert. This review authorizes only private inspection; target creation, exact parent copying and publication require separate current decisions.",
        &(restored, successor, resume),
    )?;
    let read = terminal.approve_historical(&initial)?;
    let password = terminal.secret("Restored generation capsule passphrase: ")?;
    let output = terminal.historical_output()?;
    let mut source = None;
    read.effect(&mut || {
        let opened = RestoredGenerationCapsule::open(restored, password.as_bytes())?;
        opened.external_destination(successor)?;
        read.check()?;
        // Authenticated private metadata is delivered only through the bounded
        // duplicate of this same foreground terminal, while its effect is held.
        output.json(&serde_json::json!({
            "capsule_id": opened.capsule().capsule_id(),
            "parent_manifest_digest": opened.capsule().manifest_digest(),
            "parent_generation": opened.capsule().root().generation_id(),
            "parent_profile": opened.capsule().root().profile_id(),
            "semantic_inventory_digest": opened.capsule().root().current_semantics().digest(),
            "affected_accounts": opened.capsule().root().current_semantics().accounts(),
            "unknown_external_signatures": true,
            "recovered_obligations_fenced": true,
            "financial_freshness_established": false,
        }))?;
        opened.check()?;
        read.check()?;
        source = Some(opened);
        Ok(())
    })?;
    drop(password);
    read.check()?;
    let source = source.ok_or(Error::Permission)?;
    let password = terminal.secret(if resume {
        "Exact pending layered successor passphrase: "
    } else {
        "New layered successor storage passphrase: "
    })?;
    if !resume && *password != *terminal.secret("Repeat successor passphrase: ")? {
        return Err(Error::Authentication);
    }
    let plan_review = review(
        "Create or authenticate ONLY the exact pending successor plan and independently wrapped key intent for this complete parent snapshot. New creation uses fresh host storage/transport keys, a fresh generation/profile and a fresh parent-copy key. Resume reuses only the exact authenticated pending plan, source, target and keys, never old permission. The authenticated archived-snapshot account set below is mandatory. Existing, partial or mismatched output is preserved; no reset or replacement is permitted. No parent data copy, old enrollment, signer authority or financial operation is approved here.",
        &serde_json::json!({
            "restored_capsule": restored,
            "target": successor,
            "exact_resume": resume,
            "capsule_id": source.capsule().capsule_id(),
            "parent_manifest_digest": source.capsule().manifest_digest(),
            "parent_generation": source.capsule().root().generation_id(),
            "parent_profile": source.capsule().root().profile_id(),
            "semantic_inventory_digest": source.capsule().root().current_semantics().digest(),
            "affected_accounts": source.capsule().root().current_semantics().accounts(),
        }),
    )?;
    read.check()?;
    let plan_approval = terminal.approve_historical(&plan_review)?;
    let mut source = Some(source);
    let mut pending = None;
    plan_approval.effect(&mut || {
        let source = source.take().ok_or(Error::Permission)?;
        pending = Some(if resume {
            PendingLayeredGeneration::resume(source, successor, password.as_bytes())?
        } else {
            PendingLayeredGeneration::create(source, successor, password.as_bytes())?
        });
        plan_approval.check()
    })?;
    drop(password);
    let pending = pending.ok_or(Error::Permission)?;
    pending.check()?;
    let copy_scope = CopyScope::for_copy(
        pending.source.capsule().archive(),
        &pending.directory.path(PARENT_CAPSULE)?,
        &pending.parent_key()?,
    )?;
    let construction_review = review(
        "Construct this exact restricted layered successor. Copy the WHOLE parent graph under the independent committed copy key, retain every original identity and ancestor, preserve Store row identities, lineage, charges, fences and unknown exposures, and initialize fresh empty auxiliary queues. A complete existing exact parent copy is verified before reuse; partial or corrupt copies are preserved and rejected. Source files stay immutable. Fresh enrollment is required. Financial freshness remains false; no old permit, signing, witness writer recovery, replay or submission is authorized.",
        &serde_json::json!({
            "plan_digest": pending.plan_digest,
            "plan": pending.plan,
            "exact_parent_copy": copy_scope,
        }),
    )?;
    plan_approval.check()?;
    let construction = terminal.approve_historical(&construction_review)?;
    // construct itself consumes the one-use effect around EVERY copy/Store/
    // auxiliary write. Wrapping it in a second effect would deadlock or reuse it.
    let constructed = pending.construct(&construction)?;
    construction.check()?;
    let p = &constructed.pending;
    p.check()?;
    let accounts_review = terminal.approve_historical(
        "Display the exact authenticated archived-snapshot account set for this pending layered successor on this foreground terminal. Every account requires fresh installed-signer continuity and a separate later signer-native publication admission; no saved evidence or admission can fill an account slot.",
    )?;
    accounts_review.effect(&mut || {
        p.check()?;
        output.json(&serde_json::json!({
            "generation_id": p.generation_id(),
            "inventory_digest": p.inventory_digest(),
            "affected_accounts": p.plan.affected_accounts,
        }))?;
        accounts_review.check()
    })?;
    let signers = if p.plan.affected_accounts.is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(&terminal.ask(
            "Exact signer socket/account_id/network_profile_id/writer_epoch/witness JSON array for ALL displayed accounts: ",
        )?)?
    };
    let requests = signer_requests(
        signers,
        &p.plan.affected_accounts,
        p.inventory_digest(),
        p.generation_id(),
    )?;
    let mut paired = Vec::with_capacity(requests.len());
    for request in requests {
        let detail = review(
            "Request fresh pairing with this independently installed signer for the exact account-wide host-recovery history scope. Its own native approval is required. This does not approve continuity disclosure, publication, signing, writer recovery or submission.",
            &request,
        )?;
        let pairing = terminal.approve_historical(&detail)?;
        let mut client = None;
        pairing.effect(&mut || {
            p.check()?;
            client = Some(
                OriginalHistoryClient::pair(
                    InstalledSignerProvider::load().map_err(|_| Error::Permission)?,
                    &request.socket,
                    "wholepact-native-host-recovery",
                    PairScope {
                        account_id: request.continuity.account_id.clone(),
                        agreement_id: "host-recovery".into(),
                        participant_id: "host-recovery".into(),
                        manifest_digest: p.plan.inventory_digest.clone(),
                        history_read: true,
                        authorization_export: true,
                        preconstruction_export: false,
                    },
                )
                .map_err(|_| Error::Permission)?,
            );
            pairing.check()
        })?;
        paired.push((client.ok_or(Error::Permission)?, request.continuity));
    }
    // Finish all pairings before taking continuity snapshots. Every disclosure
    // still gets a separate current local effect and independent signer review.
    let mut evidence = Vec::with_capacity(paired.len());
    for (client, request) in &paired {
        let detail = review(
            "Request separate installed-signer native approval to disclose complete historical exposure for this exact account, writer, witness and successor inventory. Every returned permit remains conservatively executable. This read-only disclosure neither recovers a writer nor admits publication or financial activity.",
            request,
        )?;
        let continuity = terminal.approve_historical(&detail)?;
        continuity.effect(&mut || {
            p.check()?;
            let lease = client
                .acquire_host_recovery_continuity_v3(request)
                .map_err(|_| Error::Permission)?;
            lease.check_current().map_err(|_| Error::Permission)?;
            continuity.check()?;
            evidence.push(lease.evidence().clone());
            // Drop the read-only signer fence before distinct publication review.
            drop(lease);
            continuity.check()
        })?;
    }
    let evidence_digests = evidence
        .iter()
        .map(|item| {
            Ok((
                item.request.account_id.clone(),
                item.digest().map_err(|_| Error::Authentication)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let staging_review = review(
        "Stage the exact NEW signer continuity snapshots into this pending successor's encrypted publication manifest and conservative obligation fences. The complete authenticated archived-snapshot account set is mandatory; exact matching releases retain their complete binding and unmatched releases stay unknown. Consumed capacity remains charged, old obligations stay fenced and financial freshness remains false. If an existing pending publication snapshot differs, preserve this target and use a fresh target with fresh reviews. Saved admissions cannot be reused. This decision does not write the final commit marker.",
        &serde_json::json!({
            "target": successor,
            "plan_digest": p.plan_digest,
            "generation_id": p.generation_id(),
            "inventory_digest": p.inventory_digest(),
            "continuity_evidence_digests": evidence_digests,
            "unknown_external_signatures": true,
            "recovered_obligations_fenced": true,
            "financial_freshness_established": false,
        }),
    )?;
    let staging = terminal.approve_historical(&staging_review)?;
    let mut constructed = Some(constructed);
    let mut evidence = Some(evidence);
    let mut prepared = None;
    staging.effect(&mut || {
        prepared = Some(
            constructed
                .take()
                .ok_or(Error::Permission)?
                .prepare_publication_v3(evidence.take().ok_or(Error::Permission)?)?,
        );
        staging.check()
    })?;
    let prepared = prepared.ok_or(Error::Permission)?;
    let requests = prepared.requests()?;
    let publication_review = review(
        "Publish ONLY this exact restricted layered generation manifest after separate fresh signer-native publication reviews for every account. These admissions are informational per-account snapshots, not a simultaneous witness cutoff. Unknown external signatures remain possible, every recovered obligation remains fenced and financial freshness remains false. Financial workflows remain unavailable in this implementation; future support requires fresh actual signer/witness authority and fresh enrollment. Preserve the complete target if the result or final acknowledgment is lost; never reset it or infer that publication did not occur.",
        &serde_json::json!({
            "target": successor,
            "manifest_digest": prepared.manifest_digest(),
            "account_publication_requests": requests,
        }),
    )?;
    staging.check()?;
    let approval = terminal.approve_publication(prepared.manifest_digest(), &publication_review)?;
    let mut admissions = Vec::with_capacity(requests.len());
    for request in requests {
        approval.check()?;
        let client = paired
            .iter()
            .find(|(_, continuity)| continuity == &request.continuity)
            .map(|(client, _)| client)
            .ok_or(Error::Authentication)?;
        let lease = client
            .acquire_host_recovery_publication_v3(&request)
            .map_err(|_| Error::Permission)?;
        approval.check()?;
        admissions.push(lease.admit().map_err(|_| Error::Permission)?);
        approval.check()?;
    }
    // The publication owner reauthenticates parent graph, plan/key, Store/fence
    // batch and empty fresh queues. Its consumed native approval spans marker
    // creation and fsync. A late error cannot prove that marker was not written.
    prepared
        .publish(admissions, approval)
        .map_err(|_| Error::GenerationArchiveIncomplete)?;
    terminal.message("Restricted layered successor published and locked. Preserve the complete target and quarantined parent. Explicit unlock and fresh native enrollment are required. Original history, consumed capacity, fenced obligations and unknown exposure remain retained. Financial workflows remain disabled and financial freshness remains false; no signature, proof or submission was produced.\n")
        .map_err(|_| Error::GenerationArchiveIncomplete)
}
