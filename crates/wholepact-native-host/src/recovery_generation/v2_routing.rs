//! Explicit complete-origin protocol routing. Availability remains denied before
//! filesystem access, native prompting, credential reads or signer contact.
use super::*;
use wholepact_signer::authority_bridge::host_recovery_ipc::v2::HostRecoveryContinuityRequestV2;

pub(crate) fn require_available() -> Result<()> {
    wholepact_signer::authority_bridge::host_recovery_ipc::v2::require_complete_origin_endpoint()
        .map_err(|_| Error::CompleteOriginRecoveryUnavailable)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignerInput {
    socket: PathBuf,
    account_id: String,
    network_profile_id: String,
    writer_epoch: u64,
    witness: wholepact_authority::WitnessDisclosureDescriptor,
}

#[derive(Serialize)]
pub(super) struct SignerRequest {
    pub(super) socket: PathBuf,
    pub(super) continuity: HostRecoveryContinuityRequestV2,
}

/// Validate the entire authenticated account set before contacting any signer.
/// A late duplicate, omission or mismatched witness must not cause a partial
/// account-wide disclosure while the caller is still correcting its input.
pub(super) fn signer_requests(
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
        let continuity = HostRecoveryContinuityRequestV2 {
            schema_version: 2,
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

pub(crate) fn activate_original(
    terminal: crate::terminal::Terminal,
    profile: &std::path::Path,
    backup: &std::path::Path,
    successor: &std::path::Path,
    resume: bool,
) -> Result<()> {
    use std::time::{Duration, Instant};
    use wholepact_signer::authority_bridge::provider::InstalledSignerProvider;
    use wholepact_signer::{authority_bridge::ipc::OriginalHistoryClient, ipc::PairScope};
    require_available()?;
    terminal.confirm(&format!("READ HISTORICAL PRIVATE DATA and prepare a separately encrypted restricted successor. Read every original wallet, proof, signature, transaction, transport and observation row. Originals stay immutable. Restored profile: {}. Original backup: {}. Target: {}. This does not approve signer disclosure, signing, submission, old permits, or renewed financial confidence.", profile.display(), backup.display(), successor.display()))?;
    let expires = Instant::now() + Duration::from_secs(300);
    let restored_password = terminal.secret("Restored profile passphrase: ")?;
    let backup_password = terminal.secret("Original backup passphrase: ")?;
    let target_password = terminal.secret(if resume {
        "Pending successor passphrase: "
    } else {
        "New successor storage passphrase: "
    })?;
    if !resume && *target_password != *terminal.secret("Repeat successor passphrase: ")? {
        return Err(Error::Authentication);
    }
    let generation = if resume {
        PendingGeneration::pending_identifier(successor, target_password.as_bytes())?
    } else {
        hex::encode(crate::random::<32>()?)
    };
    let inventory = if resume {
        crate::recovery_inventory::prepare_for_resume(
            profile,
            backup,
            successor,
            generation,
            restored_password.as_bytes(),
            backup_password.as_bytes(),
            expires,
        )?
    } else {
        crate::recovery_inventory::prepare(
            profile,
            backup,
            successor,
            generation,
            restored_password.as_bytes(),
            backup_password.as_bytes(),
            expires,
        )?
    };
    drop(restored_password);
    drop(backup_password);
    terminal.confirm(&format!("Construct exact restricted generation {} for inventory {} at {}. All recovered obligations and grants remain fenced; old proof, dispatch and observation queues are historical only. Fresh host storage/transport keys and fresh enrollment are required. Unknown external signatures remain possible. Preserve this entire target and the originals. Backup and historical export require separate exact review and may refuse unsupported origins. No financial operation is authorized.", inventory.generation_id(), inventory.digest()?, successor.display()))?;
    if Instant::now() >= expires {
        return Err(Error::Permission);
    }
    let pending = if resume {
        PendingGeneration::resume(inventory, target_password.as_bytes())?
    } else {
        PendingGeneration::create(inventory, target_password.as_bytes())?
    };
    drop(target_password);
    let constructed = pending.construct()?;
    let p = &constructed.pending;
    terminal.json(&p.plan.affected_accounts)?;
    let signers: Vec<SignerInput> = serde_json::from_str(&terminal.ask(
        "Exact signer socket/account/network/writer_epoch/witness JSON array for these accounts: ",
    )?)?;
    let requests = signer_requests(
        signers,
        &p.plan.affected_accounts,
        &p.plan.inventory_digest,
        &p.plan.generation_id,
    )?;
    let mut paired = Vec::with_capacity(requests.len());
    for signer in requests {
        let request = signer.continuity;
        terminal.json(&request)?;
        terminal.confirm(&format!("Request separate installed-signer native approval to disclose complete account-wide historical exposure for {} via {} into this exact restricted generation? No signing, witness writer recovery or financial permission is requested.", request.account_id, signer.socket.display()))?;
        let client = OriginalHistoryClient::pair(
            InstalledSignerProvider::load().map_err(|_| Error::Permission)?,
            &signer.socket,
            "wholepact-native-host-recovery",
            PairScope {
                account_id: request.account_id.clone(),
                agreement_id: "host-recovery".into(),
                participant_id: "host-recovery".into(),
                manifest_digest: p.plan.inventory_digest.clone(),
                history_read: true,
                authorization_export: true,
                preconstruction_export: false,
            },
        )
        .map_err(|_| Error::Permission)?;
        paired.push((client, request));
    }
    let mut evidence = Vec::new();
    for (client, request) in &paired {
        let lease = client
            .acquire_host_recovery_continuity_v2(request)
            .map_err(|_| Error::Permission)?;
        lease.check_current().map_err(|_| Error::Permission)?;
        evidence.push(lease.evidence().clone());
        drop(lease);
    }
    let prepared = constructed.prepare_publication_v2(evidence)?;
    let requests = prepared.requests()?;
    let approval = terminal.approve_publication(prepared.manifest_digest(), &format!("Publish exact restricted host generation manifest {} at {} after the separate signer-native publication reviews. These per-account admissions are informational snapshots, not a simultaneous witness cutoff. Recovered obligations remain fenced; every later financial action requires fresh actual signer/witness authority. Old credentials and confidence remain unusable.", prepared.manifest_digest(), successor.display()))?;
    let mut admissions = Vec::new();
    for request in requests {
        approval.check()?;
        let client = paired
            .iter()
            .find(|(_, r)| r == &request.continuity)
            .map(|(c, _)| c)
            .ok_or(Error::Authentication)?;
        let lease = client
            .acquire_host_recovery_publication_v2(&request)
            .map_err(|_| Error::Permission)?;
        admissions.push(lease.admit().map_err(|_| Error::Permission)?);
    }
    prepared.publish(admissions, approval)?;
    terminal.message("Restricted informational successor published and locked. Opening it grants no enrollment or financial capability. Original history and unknown exposure remain retained; recovered obligations cannot be replaced or automatically released. No financial freshness, signature, proof or submission was produced.\n")
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
    fn explicit_v2_stays_unavailable_before_source_or_target_access() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("empty-source");
        let target = root.path().join("never-created");
        std::fs::create_dir(&source).unwrap();
        for resume in [false, true] {
            assert!(matches!(
                activate_original(
                    crate::terminal::Terminal::disconnected_for_test(),
                    &source,
                    &source,
                    &target,
                    resume
                ),
                Err(Error::CompleteOriginRecoveryUnavailable)
            ));
            assert!(matches!(
                super::super::layered_activate_v2::activate(
                    crate::terminal::Terminal::disconnected_for_test(),
                    &source,
                    &target,
                    resume
                ),
                Err(Error::CompleteOriginRecoveryUnavailable)
            ));
            assert!(!target.exists());
            assert_eq!(std::fs::read_dir(&source).unwrap().count(), 0);
        }
    }
    #[test]
    fn v2_request_inventory_has_explicit_protocol_and_no_imported_grants() {
        let requests = validate(vec![signer("a"), signer("b")]).unwrap();
        assert!(requests.iter().all(|r| r.continuity.schema_version == 2));
        let mut input = serde_json::json!({"socket":"/synthetic-not-opened/signer.sock","account_id":"a","network_profile_id":"synthetic-network","writer_epoch":1,"witness":signer("a").witness});
        input["saved_admission"] = true.into();
        assert!(serde_json::from_value::<SignerInput>(input).is_err());
    }
}
