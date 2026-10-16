//! Foreground-only composition for a genuine restored generation capsule.
//! Explicit CLI composition retains permanent financial denial in the Host.
//! Every admission is obtained anew; saved plans and audit records are not grants.
use super::layered::{PARENT_CAPSULE, PendingLayeredGeneration};
use crate::{Error, Result, generation_restore::RestoredGenerationCapsule, terminal::Terminal};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use wholepact_signer::{
    authority_bridge::{
        host_recovery_ipc::HostRecoveryContinuityRequest, ipc::OriginalHistoryClient,
        provider::InstalledSignerProvider,
    },
    ipc::PairScope,
};
use wholepact_storage_security::{
    bundle::recovery::evidence::history::MAX_HISTORICAL_METADATA_BYTES,
    generation_archive::CopyScope,
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerInput {
    socket: PathBuf,
    account_id: String,
    network_profile_id: String,
    writer_epoch: u64,
    witness: wholepact_authority::WitnessDisclosureDescriptor,
}

#[derive(Serialize)]
struct SignerRequest {
    socket: PathBuf,
    continuity: HostRecoveryContinuityRequest,
}

/// Validate the entire authenticated account set before contacting any signer.
/// A late duplicate, omission or mismatched witness must not cause a partial
/// account-wide disclosure while the caller is still correcting its input.
fn signer_requests(
    signers: Vec<SignerInput>,
    expected: &BTreeSet<String>,
    inventory_digest: &str,
    generation_id: &str,
) -> Result<Vec<SignerRequest>> {
    super::canonical_hash(inventory_digest)?;
    super::canonical_hash(generation_id)?;
    if signers.len() != expected.len() {
        return Err(Error::Invalid);
    }
    let mut accounts = BTreeSet::new();
    let mut requests = Vec::with_capacity(signers.len());
    for signer in signers {
        crate::id(&signer.account_id)?;
        crate::files::validate_absolute(&signer.socket)?;
        if !accounts.insert(signer.account_id.clone()) || !expected.contains(&signer.account_id) {
            return Err(Error::Invalid);
        }
        let continuity = HostRecoveryContinuityRequest {
            schema_version: 1,
            inventory_digest: inventory_digest.into(),
            generation_id: generation_id.into(),
            account_id: signer.account_id,
            network_profile_id: signer.network_profile_id,
            expected_writer_epoch: signer.writer_epoch,
            expected_witness: signer.witness,
        };
        continuity.validate().map_err(|_| Error::Invalid)?;
        requests.push(SignerRequest {
            socket: signer.socket,
            continuity,
        });
    }
    if &accounts != expected {
        return Err(Error::Invalid);
    }
    requests.sort_by(|a, b| a.continuity.account_id.cmp(&b.continuity.account_id));
    Ok(requests)
}

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
                .acquire_host_recovery_continuity(request)
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
                .prepare_publication(evidence.take().ok_or(Error::Permission)?)?,
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
            .acquire_host_recovery_publication(&request)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn signer(account: &str) -> SignerInput {
        SignerInput {
            socket: PathBuf::from("/synthetic-not-opened/signer.sock"),
            account_id: account.into(),
            network_profile_id: "synthetic-network".into(),
            writer_epoch: 1,
            witness: wholepact_authority::WitnessDisclosureDescriptor {
                endpoint: "127.0.0.1:4444".into(),
                server_name: "localhost".into(),
                witness_id: "synthetic-witness".into(),
                account_id: account.into(),
                network_profile_id: "synthetic-network".into(),
                policy_digest: "33".repeat(32),
                pinned_server_certificate_digest: "44".repeat(32),
            },
        }
    }
    fn validate(signers: Vec<SignerInput>) -> Result<Vec<SignerRequest>> {
        signer_requests(
            signers,
            &BTreeSet::from(["a".into(), "b".into()]),
            &"11".repeat(32),
            &"22".repeat(32),
        )
    }

    #[test]
    fn complete_account_set_is_validated_before_any_signer_contact() {
        let requests = validate(vec![signer("b"), signer("a")]).unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|r| r.continuity.account_id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert!(validate(vec![signer("a")]).is_err());
        assert!(validate(vec![signer("a"), signer("a")]).is_err());
        assert!(validate(vec![signer("a"), signer("c")]).is_err());
        let mut mismatched = signer("b");
        mismatched.witness.account_id = "a".into();
        assert!(validate(vec![signer("a"), mismatched]).is_err());
        let mut mismatched = signer("b");
        mismatched.network_profile_id = "another-network".into();
        assert!(validate(vec![signer("a"), mismatched]).is_err());
        let mut relative = signer("b");
        relative.socket = "relative.sock".into();
        assert!(validate(vec![signer("a"), relative]).is_err());
        let mut stale = signer("b");
        stale.writer_epoch = 0;
        assert!(validate(vec![signer("a"), stale]).is_err());
        assert!(
            signer_requests(vec![], &BTreeSet::new(), &"11".repeat(32), &"22".repeat(32))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn imported_authority_fields_and_render_expansion_are_rejected() {
        let input = serde_json::json!({
            "socket": "/synthetic-not-opened/signer.sock",
            "account_id": "a", "network_profile_id": "synthetic-network", "writer_epoch": 1,
            "witness": signer("a").witness,
            "saved_admission": true,
        });
        assert!(serde_json::from_value::<SignerInput>(input).is_err());
        assert!(
            review(
                "Bounded synthetic review",
                &serde_json::json!({"unknown": true})
            )
            .is_ok()
        );
        assert!(review("", &"a".repeat(MAX_HISTORICAL_METADATA_BYTES)).is_err());
        let unicode = "é".repeat(24_000);
        assert!(unicode.len() < MAX_HISTORICAL_METADATA_BYTES);
        assert!(review("", &unicode).is_err());
    }

    #[test]
    fn disconnected_foreground_cannot_open_a_source_or_create_a_target() {
        use std::os::unix::fs::DirBuilderExt;
        // Valid private empty source directory, deliberately no capsule/vault or
        // lock files. The first decision must fail before even opening it.
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("empty-source");
        let target = root.path().join("never-created-successor");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&source)
            .unwrap();
        assert_eq!(std::fs::read_dir(&source).unwrap().count(), 0);
        assert!(matches!(
            activate(Terminal::disconnected_for_test(), &source, &target, false),
            Err(Error::Terminal)
        ));
        assert_eq!(std::fs::read_dir(&source).unwrap().count(), 0);
        assert!(!target.try_exists().unwrap());
        assert!(matches!(
            activate(Terminal::disconnected_for_test(), &source, &target, true),
            Err(Error::Terminal)
        ));
        assert_eq!(std::fs::read_dir(&source).unwrap().count(), 0);
        assert!(!target.try_exists().unwrap());
    }
}
