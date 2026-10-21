//! Disposable CI setup only. Three genuine completed births and their maintained
//! predecessor journals, not a fabricated ledger, cloned namespace or permit.
//! This stops before viewing-wallet, funding, PCZT, proof, signing and dispatch.
//! Only the prospective candidate/material claims below are synthetic public
//! values. A later positive result qualifies W's one-effect kernel, not a real
//! Signer/Host financial flow or attended-human approval.
use super::*;
use sha2::{Digest, Sha256};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use wholepact_authority::{
    AuthorityHead, OwnerControlRequest, ReconciledAuthorityHistory,
    durable_delivery_admission_v2::{canonical_durable_authorization_id_v2,
        original_host_generation_binding_digest_v2, prepare_durable_delivery_admission_request_v2},
    durable_delivery_scope_v2::*,
    durable_payment_v1::{DurableFixedCandidateBindingV1, DurablePaymentAdmissionTermsV1},
    manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2,
};

const CONTAINER_ROOT: &str = "/ci-fixture";
const CHILD_HANDOFF: &str = "pristine-handoff.json";
const PARENT_HANDOFF: &str = "handoff.json";
const MAX_HANDOFF: usize = 2 * 1024 * 1024;
const LIMIT: Duration = Duration::from_secs(900);

fn authority<T>(result: wholepact_authority::Result<T>) -> Result<T> {
    result.map_err(|error| {
        super::super::pristine_diagnostics_v1::source_authority_error(&error);
        Error::Authentication
    })
}
fn public_claim(label: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"wholepact:isolated-coordinator-public-claim:v1\0");
    h.update(label.as_bytes());
    hex::encode(h.finalize())
}

/// Independent encoding of inert fixed-candidate data only. The maintained
/// validator checks this projection; it never represents an actual PCZT proof.
fn fixed_claim(network: &str, agreement: &str, obligation: &str) -> Result<DurableFixedCandidateBindingV1> {
    let mut fixed = DurableFixedCandidateBindingV1 {
        schema_version: 1, network_profile_id: network.to_owned(),
        agreement_id: agreement.to_owned(), obligation_id: obligation.to_owned(),
        proposal_id: "isolated-w-one-effect-not-financial-v1".into(), revision: 1, expiry_height: 1,
        proposal_digest: public_claim("proposal"), manifest_digest: public_claim("manifest"),
        unsigned_artifact_digest: public_claim("unsigned-not-created"), proved_artifact_digest: public_claim("proved-not-created"),
        effects_commitment: public_claim("effects"), policy_digest: public_claim("candidate-policy"),
        review_binding: public_claim("review"), action_mapping_digest: public_claim("actions"),
        anchor: public_claim("unfunded-anchor"), proposal_binding: String::new(),
    };
    let mut h = Sha256::new();
    h.update(b"wholepact:durable-fixed-proposal:pczt-0.10.0-pre.1:v1\0");
    for value in [fixed.schema_version, fixed.revision, fixed.expiry_height] { h.update(value.to_le_bytes()); }
    for value in [&fixed.network_profile_id, &fixed.agreement_id, &fixed.obligation_id,
        &fixed.proposal_id, &fixed.proposal_digest, &fixed.manifest_digest,
        &fixed.unsigned_artifact_digest, &fixed.proved_artifact_digest, &fixed.effects_commitment,
        &fixed.policy_digest, &fixed.review_binding, &fixed.action_mapping_digest, &fixed.anchor] {
        h.update((value.len() as u64).to_le_bytes()); h.update(value.as_bytes());
    }
    fixed.proposal_binding = hex::encode(h.finalize());
    authority(fixed.validate())?;
    Ok(fixed)
}

fn prospective_scope(
    history: &ReconciledAuthorityHistory,
    extension: &ManualRosterEnrollmentExtensionV2,
    other: &ManualRosterEnrollmentExtensionV2,
    from_ms: u64,
    until_ms: u64,
) -> Result<DurableDeliveryScopeV2> {
    let original = &extension.account_extension.terms;
    let policy = history.account_policy();
    let fixed = fixed_claim(&original.identity.network_profile_id, &original.scope.agreement_id, &original.scope.obligation_id)?;
    let mut owners = [extension, other].into_iter().map(|e| {
        let terms = &e.account_extension.terms;
        Ok(DurableDeliveryOwnerLineageV2 {
            account_id: terms.identity.account_id.clone(), participant_id: terms.scope.participant_id.clone(),
            original_authorization_id: authority(canonical_durable_authorization_id_v2(&fixed, &terms.identity))?,
        })
    }).collect::<Result<Vec<_>>>()?;
    owners.sort_by(|a,b| a.account_id.cmp(&b.account_id));
    let material_scopes = owners.iter().map(|owner| DurableDeliveryMaterialScopeRefV2 {
        account_id: owner.account_id.clone(), original_scope_digest: public_claim("material-not-created"),
        valid_from_unix_seconds: from_ms / 1000, valid_until_unix_seconds: until_ms / 1000,
    }).collect();
    let authorization = DurablePaymentAdmissionTermsV1 {
        version: 1, identity: original.identity.clone(), original_policy_digest: authority(policy.policy_digest())?,
        original_genesis_digest: original.account_use_genesis_digest.clone(),
        original_birth_commit_digest: original.birth_commit_digest.clone(),
        original_roster_extension_digest: authority(extension.digest())?,
        original_enrollment_ref: extension.account_extension.enrollment_ref.clone(),
        writer_certificate_digest: original.signer.writer_certificate_digest.clone(),
        authorization_id: authority(canonical_durable_authorization_id_v2(&fixed, &original.identity))?,
        recipient_policy_scope_digest: original.scope.recipient_scope_digests.first().ok_or(Error::Invalid)?.clone(),
        concrete_recipient_scope_digest: public_claim("unfunded-recipient-claim"),
        inputs: vec![wholepact_authority::InputReservation { input_id: "unfunded-public-input-claim".into(),
            nullifier: public_claim("unfunded-nullifier-claim"), action_index: 0, value_zatoshis: 100 }],
        maximum_debit_zatoshis: 100, fee_share_zatoshis: 1, transaction_fee_zatoshis: 2,
        valid_from_ms: from_ms, valid_until_ms: until_ms, fixed,
    };
    let scope = DurableDeliveryScopeV2 {
        version: 2, accepted_manifest_ref: public_claim("manifest-not-accepted-by-signer"),
        original_writer_epoch: policy.initial_writer_epoch,
        witness: history.pending_birth_commit().ok_or(Error::Authentication)?.request.disclosure.clone(),
        delivery: DurableDeliveryPlanV2 {
            dispatcher: DurableDeliveryDispatcherV2 { principal_id: "inert-unfunded-dispatcher-claim".into(),
                public_identity_commitment: public_claim("dispatcher-no-key-generated"),
                authentication_profile: DurableDeliveryAuthenticationProfileV2::OriginalProtectedHostDispatcherV2,
                custody_policy_commitment: public_claim("no-dispatcher-custody") },
            original_host_generation_binding_digest: authority(original_host_generation_binding_digest_v2(&original.host))?,
            original_host_profile_id: original.host.profile_id.clone(), submission_journal_identity: public_claim("no-submission-journal"),
            submission_operation_id: "isolated-no-submission-operation-v1".into(),
            provider: wholepact_core::manual_construction::PreconstructionProvider {
                source_id: "never-contacted-provider".into(), endpoint: "https://provider.invalid".into(),
                trust_profile: "single_tls_provider_report_not_consensus".into() },
            route: DurableDeliveryRouteV2::Direct {}, owners, valid_from_ms: from_ms, valid_until_ms: until_ms,
            minimum_expiry_margin_blocks: 1, maximum_fresh_admission_lifetime_ms: 30_000,
            maximum_explicitly_approved_attempts: 1,
            extraction_rule: DurableDeliveryExtractionRuleV2::FirstDurablyRetainedVerifiedExtraction,
            retry_rule: DurableDeliveryRetryRuleV2::SameRetainedBytesWithFreshAdmission,
            attempt_rule: DurableDeliveryAttemptRuleV2::ExplicitImmediateHostDecision,
        },
        original_ceilings: DurableDeliveryOriginalCeilingsV2 { payment_valid_from_ms: from_ms, payment_valid_until_ms: until_ms,
            enrollment_expires_at_ms: original.scope.expires_at_ms, policy_expires_at_ms: policy.policy_expires_at_ms,
            material_scopes }, authorization,
        disclosure_rule: DurableDeliveryDisclosureRuleV2::WholeTransactionAndConnectionMetadataToProviderCommitmentsAndLinkageToWitness,
    };
    authority(scope.validate())?;
    Ok(scope)
}

pub(in super::super) fn prepare_child(terminal: crate::terminal::Terminal) -> Result<()> {
    let _guard = super::super::pristine_diagnostics_v1::begin_source();
    let result = prepare_child_inner(terminal);
    if let Err(error) = &result {
        super::super::pristine_diagnostics_v1::source_host_error(error);
    }
    result
}

fn source_stage(boundary: super::super::safe_diagnostics_v1::Boundary) {
    super::super::safe_diagnostics_v1::emit(boundary, super::super::safe_diagnostics_v1::Outcome::Begin);
}

fn prepare_child_inner(terminal: crate::terminal::Terminal) -> Result<()> {
    use super::super::safe_diagnostics_v1::Boundary;
    let cutoff = super::private_fixed_v2::child_original_cutoff()?;
    let initial = initial::prepare_pristine_coordinator_v1(terminal)?;
    let initial::PrivateWorkspaceInitialV1 { signers, mut witness, mut host, born, temporary,
        roster_intents, roster_requests, roster_signed_extension_files, roster_original_policy_files,
        payment_receiver, expiry_ms } = initial;
    // Both participants are the actual two maintained roster accounts; the
    // selected target is born[1], not an additional fourth account.
    source_stage(Boundary::PristineOriginalHistory);
    let own = authority(witness.observe_original_roster_attempt_v2(&born[1].account_id))?;
    let other = authority(witness.observe_original_roster_attempt_v2(&born[2].account_id))?;
    let history = authority(witness.original_pristine_delivery_history_v1(&born[1].account_id))?;
    let other_history = authority(witness.original_pristine_delivery_history_v1(&born[2].account_id))?;
    if authority(history.manual_roster_enrollment_extension(&own.extension.account_extension.enrollment_ref))? != Some(&own.extension)
        || authority(other_history.manual_roster_enrollment_extension(&other.extension.account_extension.enrollment_ref))? != Some(&other.extension) {
        return Err(Error::Authentication);
    }
    // Sample once, after actual setup. The original monotonic cutoff predates
    // setup and is never replaced by a new per-case or retry lifetime.
    let from_ms: u64 = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Invalid)?.as_millis().try_into().map_err(|_| Error::Invalid)?;
    let remaining: u64 = cutoff.checked_duration_since(Instant::now()).ok_or(Error::Permission)?
        .as_millis().try_into().map_err(|_| Error::Invalid)?;
    let until_ms = from_ms.checked_add(remaining).ok_or(Error::Invalid)? / 1000 * 1000;
    if until_ms <= from_ms || until_ms > expiry_ms { return Err(Error::Permission); }
    source_stage(Boundary::PristineProspectiveScope);
    let scope = prospective_scope(&history, &own.extension, &other.extension, from_ms, until_ms)?;
    let request = authority(prepare_durable_delivery_admission_request_v2(scope, &history))?;
    drop((history, other_history, own, other, roster_intents, roster_requests,
        roster_signed_extension_files, roster_original_policy_files, payment_receiver, born));
    source_stage(Boundary::PristineSignerDrain);
    signers.shutdown().map_err(|_| Error::Authentication)?;
    source_stage(Boundary::PristineHostRevoke);
    let original_host = host.take().ok_or(Error::Authentication)?;
    original_host.authority.fence.revoke()?;
    drop(original_host);
    drop(temporary);
    if Instant::now() >= cutoff { return Err(Error::Permission); }
    source_stage(Boundary::PristineOriginalPreservation);
    let bytes = authority(witness.preserve_pristine_delivery_originals_v1(&request))?;
    if bytes.is_empty() || bytes.len() > MAX_HANDOFF || Instant::now() >= cutoff { return Err(Error::Permission); }
    source_stage(Boundary::PristineCustodyHandoff);
    let root = std::env::var_os("TMPDIR").ok_or(Error::Invalid)?;
    write_new_private(&std::path::PathBuf::from(root).join(CHILD_HANDOFF), &bytes)?;
    Ok(())
}

/// Consume the one original container-owned ceiling. Never mint a replacement
/// deadline when setup is slow, and never accept an alternative textual value.
fn original_cutoff_value(raw: &str, now_ns: u64) -> std::io::Result<u64> {
    let refused = || std::io::Error::other("original cutoff refused");
    let cutoff: u64 = raw.parse().map_err(|_| refused())?;
    let maximum: u64 = LIMIT.as_nanos().try_into().map_err(|_| refused())?;
    if cutoff.to_string() != raw || cutoff <= now_ns
        || cutoff.checked_sub(now_ns).is_none_or(|remaining| remaining > maximum) {
        return Err(refused());
    }
    Ok(cutoff)
}

fn original_cutoff_ns() -> std::io::Result<u64> {
    let raw = std::env::var("WHOLEPACT_TEST_ONLY_PRIVATE_WORKFLOW_CUTOFF_NS")
        .map_err(|_| std::io::Error::other("original cutoff unavailable"))?;
    original_cutoff_value(&raw, monotonic_ns()?)
}

fn monotonic_ns() -> std::io::Result<u64> {
    let mut t = std::mem::MaybeUninit::<libc::timespec>::zeroed();
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, t.as_mut_ptr()) } != 0 { return Err(std::io::Error::last_os_error()); }
    let t = unsafe { t.assume_init() };
    let seconds = u64::try_from(t.tv_sec).map_err(|_| std::io::Error::other("clock refused"))?;
    let nanos = u64::try_from(t.tv_nsec).map_err(|_| std::io::Error::other("clock refused"))?;
    if nanos >= 1_000_000_000 { return Err(std::io::Error::other("clock refused")); }
    seconds.checked_mul(1_000_000_000).and_then(|s| s.checked_add(nanos)).ok_or_else(|| std::io::Error::other("clock refused"))
}
fn write_new_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW).open(path)?;
    file.write_all(bytes)?; file.sync_all()?;
    Ok(())
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Handoff {
    version: u16, installation: Vec<u8>, home_path: std::path::PathBuf,
    form: Form, owner_client: OwnerClient, accounts: Vec<AccountBaseline>,
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Form {
    endpoint: String, server_name: String, witness_id: String, pinned_server_certificate_digest: String,
    network_profile_id: String, expected_account_id: String, owner_certificate_der_hex: String,
    storage_key_file: String, server_certificate_der: String, server_private_key_pkcs8_der: String,
    trusted_client_root_der: String, request_json: String,
}
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct OwnerClient { certificate_der: String, private_key_pkcs8_der: String, trusted_server_root_der: String }
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AccountBaseline { account_id: String, head: AuthorityHead, original_signed_birth: String, original_source_commitment: String }

fn private_directory(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    if !path.is_absolute() || std::fs::canonicalize(path)? != path { return Err(std::io::Error::other("private path refused")); }
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY).open(path)?;
    let m = file.metadata()?;
    if !m.is_dir() || m.uid() != 10001 || m.mode() & 0o7777 != 0o700 { return Err(std::io::Error::other("private owner refused")); }
    Ok(file)
}
fn unchanged_directory(file: &std::fs::File, path: &std::path::Path) -> std::io::Result<()> {
    let held = file.metadata()?;
    let current = private_directory(path)?.metadata()?;
    if (held.dev(), held.ino(), held.uid()) != (current.dev(), current.ino(), current.uid()) {
        return Err(std::io::Error::other("private identity changed"));
    }
    Ok(())
}

fn validate_custody(root: &std::path::Path, bytes: &[u8]) -> std::io::Result<Handoff> {
    let refused = || std::io::Error::other("pristine custody refused");
    let handoff: Handoff = serde_json::from_slice(bytes).map_err(|_| refused())?;
    if handoff.version != 1 || handoff.installation.len() > 16 * 1024
        || handoff.home_path.parent() != Some(root) || handoff.accounts.len() != 3 {
        return Err(refused());
    }
    let home = private_directory(&handoff.home_path)?;
    let request: OwnerControlRequest = serde_json::from_str(&handoff.form.request_json).map_err(|_| refused())?;
    let mut ids = std::collections::BTreeSet::new();
    if request.expected_head.sequence != 4 || request.account_id != handoff.form.expected_account_id
        || !handoff.accounts.iter().all(|a| ids.insert(&a.account_id))
        || !handoff.accounts.iter().any(|a| a.account_id == request.account_id && a.head == request.expected_head) {
        return Err(refused());
    }
    for (path, name) in [(&handoff.form.storage_key_file, "synthetic-namespace.key"),
        (&handoff.form.server_certificate_der, "server.der"), (&handoff.form.server_private_key_pkcs8_der, "server.pk8"),
        (&handoff.form.trusted_client_root_der, "ca.der"), (&handoff.owner_client.certificate_der, "owner.der"),
        (&handoff.owner_client.private_key_pkcs8_der, "owner.pk8"), (&handoff.owner_client.trusted_server_root_der, "ca.der")] {
        if std::path::Path::new(path) != handoff.home_path.join(name) { return Err(refused()); }
        let m = std::fs::symlink_metadata(path)?;
        if !m.is_file() || m.uid() != 10001 || m.mode() & 0o7777 != 0o600 { return Err(refused()); }
    }
    // Storage's original nofollow/exclusion/identity comparison checks home,
    // namespace, journal directory and installation marker stamps. This creates
    // no Window, source, namespace, account or persistent trust installation.
    let installation = wholepact_storage_security::witness_namespace_fs::EphemeralWitnessInstallation::reopen_preserved_original_v2(&handoff.installation).map_err(|_| refused())?;
    let probe = installation.probe().map_err(|_| refused())?;
    if probe.root_path().parent() != Some(handoff.home_path.as_path()) { return Err(refused()); }
    drop(probe); drop(installation);
    unchanged_directory(&home, &handoff.home_path)?;
    Ok(handoff)
}

#[test]
#[ignore = "Approved disposable CI only; generates exactly three genuine unfunded accounts; never local native execution"]
fn coordinator_pristine_three_account_source_for_ui() {
    use super::super::safe_diagnostics_v1::Boundary;
    let stage = std::cell::Cell::new(Boundary::PristineSetupRoot);
    let nested_failure = std::cell::Cell::new(false);
    let result = (|| -> std::io::Result<()> {
        let base = std::path::Path::new(CONTAINER_ROOT);
        let base_file = private_directory(base)?;
        let root = tempfile::Builder::new().prefix("ui-").permissions(std::fs::Permissions::from_mode(0o700)).tempdir_in(base)?;
        let root_file = private_directory(root.path())?;
        stage.set(Boundary::PristineOriginalCutoff);
        let cutoff_ns = original_cutoff_ns()?;
        let deadline = super::private_fixed_v2::child_original_cutoff()
            .map_err(|_| std::io::Error::other("original cutoff refused"))?;
        stage.set(Boundary::PristinePredecessorProcess);
        let mut result = private_workspace_stage_v1(root, None, PrivateWorkspaceStageV1::PristineCoordinator,
            &initial::inputs(), deadline, cutoff_ns)?;
        nested_failure.set(result.pristine_first_failure.is_some());
        if result.outcome.is_err() || !result.process.verified() || result.next != result.expected
            || !result.process.status.as_ref().is_some_and(|s| s.success()) || Instant::now() >= deadline {
            return Err(std::io::Error::other("pristine predecessor or cleanup refused"));
        }
        stage.set(Boundary::PristineCustodyValidation);
        let root = result.root.take().ok_or_else(|| std::io::Error::other("original root unavailable"))?;
        unchanged_directory(&root_file, root.path())?;
        let bytes = crate::files::read_private(&root.path().join(CHILD_HANDOFF), MAX_HANDOFF)
            .map_err(|_| std::io::Error::other("private handoff refused"))?;
        let handoff = validate_custody(root.path(), &bytes)?;
        unchanged_directory(&root_file, root.path())?;
        unchanged_directory(&base_file, base)?;
        let m = root_file.metadata()?;
        let public_to_runner = serde_json::json!({"version": 1, "root_path": root.path(),
            "root_device": m.dev(), "root_inode": m.ino(), "original_monotonic_cutoff_ns": cutoff_ns,
            "fixture": handoff});
        let encoded = serde_json::to_vec(&public_to_runner).map_err(|_| std::io::Error::other("handoff encoding refused"))?;
        if encoded.len() > MAX_HANDOFF || Instant::now() >= deadline { return Err(std::io::Error::other("handoff bound refused")); }
        // Regression: consume the actual original signed JSON envelopes with
        // the same owner-client parser/verifier before publishing this fixture.
        super::pristine_owner_client_v1::check_actual_birth_envelope_contract(&encoded)?;
        stage.set(Boundary::PristineCustodyHandoff);
        let kept = root.keep();
        unchanged_directory(&root_file, &kept)?;
        // Any error after keep is not a successful custody transfer. The outer
        // disposable-container supervisor must destroy the entire namespace.
        write_new_private(&base.join(PARENT_HANDOFF), &encoded)?;
        base_file.sync_all()?;
        println!("CI_UI_FIXTURE_READY version=1 accounts=3 target_head=4 process_cleanup=true");
        Ok(())
    })();
    if result.is_err() && !nested_failure.get() {
        super::super::pristine_diagnostics_v1::emit_outer_failure(stage.get());
    }
    assert!(result.is_ok(), "bounded pristine fixture setup failed");
}

#[test]
fn prospective_fixed_claim_is_inert_and_canonically_bound() {
    // Pure immutable data only; no account, credential, socket or source owner.
    let fixed = fixed_claim("test-network", "actual-agreement", "actual-obligation").unwrap();
    assert!(fixed.validate().is_ok());
    assert_eq!(fixed.proposal_id, "isolated-w-one-effect-not-financial-v1");
    assert_eq!(fixed.proved_artifact_digest, public_claim("proved-not-created"));
    let mut changed = fixed.clone();
    changed.agreement_id = "another-agreement".into();
    assert!(changed.validate().is_err());
    assert_ne!(fixed.proposal_binding,
        fixed_claim("test-network", "another-agreement", "actual-obligation").unwrap().proposal_binding);
}

#[test]
fn pristine_handoff_fields_are_closed() {
    // Pure parser refusal, never a production importer or fabricated fixture.
    assert!(serde_json::from_str::<OwnerClient>(r#"{"certificate_der":"a","private_key_pkcs8_der":"b","trusted_server_root_der":"c","extra":true}"#).is_err());
    assert!(serde_json::from_str::<OwnerClient>(r#"{"certificate_der":"a","certificate_der":"b","private_key_pkcs8_der":"b","trusted_server_root_der":"c"}"#).is_err());
    assert_eq!(LIMIT.as_secs(), 900);
    assert_eq!(MAX_HANDOFF, 2 * 1024 * 1024);
}


#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerHandoff {
    version: u16,
    root_path: std::path::PathBuf,
    root_device: u64,
    root_inode: u64,
    original_monotonic_cutoff_ns: u64,
    fixture: Handoff,
}

/// No-journal-mutation audit only after the external supervisor has observed
/// actual W disposal and the entire product tree/group drain. Existing opener
/// locks/sidecars may be touched; no fixture is recreated, moved, or reset.
fn audit_existing_originals(expected_one_exact_append: bool) -> std::io::Result<()> {
    let refused = || std::io::Error::other("original audit refused");
    let cutoff = original_cutoff_ns()?;
    let base = std::path::Path::new(CONTAINER_ROOT);
    let base_file = private_directory(base)?;
    let bytes = crate::files::read_private(&base.join(PARENT_HANDOFF), MAX_HANDOFF)
        .map_err(|_| refused())?;
    let handoff: RunnerHandoff = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    if handoff.version != 1 || handoff.original_monotonic_cutoff_ns != cutoff
        || handoff.root_path.parent() != Some(base) {
        return Err(refused());
    }
    let root_file = private_directory(&handoff.root_path)?;
    let meta = root_file.metadata()?;
    if (meta.dev(), meta.ino()) != (handoff.root_device, handoff.root_inode) {
        return Err(refused());
    }
    let fixture = serde_json::to_vec(&handoff.fixture).map_err(|_| refused())?;
    if fixture.len() > MAX_HANDOFF { return Err(refused()); }
    validate_custody(&handoff.root_path, &fixture)?;
    let result = wholepact_authority::native_witness_owner::EphemeralNativeWitnessV1::audit_pristine_delivery_originals_v1(
        &fixture, expected_one_exact_append).map_err(|_| refused())?;
    unchanged_directory(&root_file, &handoff.root_path)?;
    unchanged_directory(&base_file, base)?;
    if monotonic_ns()? >= cutoff { return Err(refused()); }
    let encoded = serde_json::to_string(&result).map_err(|_| refused())?;
    if encoded.len() > 4096 { return Err(refused()); }
    println!("CI_UI_FIXTURE_AUDIT {encoded}");
    Ok(())
}

#[test]
#[ignore = "Approved disposable CI only, after full product disposal and process drain"]
fn coordinator_pristine_originals_after_cancel_or_blur() {
    assert!(audit_existing_originals(false).is_ok(), "bounded original audit failed");
}

#[test]
#[ignore = "Approved disposable CI only, after the sole exact append and full product drain"]
fn coordinator_originals_after_one_exact_append() {
    assert!(audit_existing_originals(true).is_ok(), "bounded original audit failed");
}

#[test]
fn pristine_original_cutoff_is_consumed_not_renewed() {
    // Pure arithmetic/parser cases only, no clock, account, process or file.
    let now = 10_000_000_000;
    let original = now + 900_000_000_000;
    assert_eq!(original_cutoff_value(&original.to_string(), now).unwrap(), original);
    assert_eq!(original_cutoff_value(&original.to_string(), now + 123).unwrap(), original);
    for raw in ["".to_owned(), "0".to_owned(), "+10".to_owned(), "010".to_owned(),
        format!("{original} "), (now - 1).to_string(), now.to_string(),
        (original + 1).to_string(), "18446744073709551616".to_owned()] {
        assert!(original_cutoff_value(&raw, now).is_err());
    }
    assert!(original_cutoff_value(&original.to_string(), original).is_err());
}
