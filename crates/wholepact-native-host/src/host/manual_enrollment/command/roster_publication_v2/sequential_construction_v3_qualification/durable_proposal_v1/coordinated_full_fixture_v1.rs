//! Test-only cut after actual FINAL-V4 fixed proof/dispatcher publication, before
//! any V3 recipient preparation or admission. Output is private inert selection
//! data. The later full original product must perform every native operation.
use super::*;
use serde::Deserialize;
use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, path::{Path, PathBuf}, time::Instant};
use worker::{JoinedSignerCommandV1 as C, JoinedSignerReplyV1 as R};
use delivery_admission_v2::OriginalDisclosureV2;

pub(super) const READY_FILE: &str = "coordinated-financial-pre-v3-fixture-v1.json";
const MAX_HANDOFF: usize = 1024 * 1024;

// Diagnostic-only tokens; neither a readiness marker nor native permission.
const POST_INPUT_PREFIX: &[u8] = b"SYNTHETIC_COORDINATED_POST_INPUT_PHASE=";
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) enum PostInputPhase {
    FinalInspection,
    InputEntry,
    AnchorDrain,
    SourceOneOpen,
    SourceOneMetadata,
    SourceOnePreserve,
    SourceTwoOpen,
    SourceTwoMetadata,
    SourceTwoPreserve,
    SignerShutdown,
    HostFence,
    WitnessDescriptor,
    HandoffWrite,
    ExternalControls,
    ExternalBootstrap,
    Ready,
}
impl PostInputPhase {
    pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) fn label(self) -> &'static str {
        match self {
            Self::FinalInspection => "post_final_inspection",
            Self::InputEntry => "post_input_entry",
            Self::AnchorDrain => "post_anchor_drain",
            Self::SourceOneOpen => "post_source_one_open",
            Self::SourceOneMetadata => "post_source_one_metadata",
            Self::SourceOnePreserve => "post_source_one_preserve",
            Self::SourceTwoOpen => "post_source_two_open",
            Self::SourceTwoMetadata => "post_source_two_metadata",
            Self::SourceTwoPreserve => "post_source_two_preserve",
            Self::SignerShutdown => "post_signer_shutdown",
            Self::HostFence => "post_host_fence",
            Self::WitnessDescriptor => "post_witness_descriptor",
            Self::HandoffWrite => "post_handoff_write",
            Self::ExternalControls => "post_external_controls",
            Self::ExternalBootstrap => "post_external_bootstrap",
            Self::Ready => "post_ready",
        }
    }
    fn parse(value: &[u8]) -> Option<Self> {
        match value {
            b"post_final_inspection" => Some(Self::FinalInspection),
            b"post_input_entry" => Some(Self::InputEntry),
            b"post_anchor_drain" => Some(Self::AnchorDrain),
            b"post_source_one_open" => Some(Self::SourceOneOpen),
            b"post_source_one_metadata" => Some(Self::SourceOneMetadata),
            b"post_source_one_preserve" => Some(Self::SourceOnePreserve),
            b"post_source_two_open" => Some(Self::SourceTwoOpen),
            b"post_source_two_metadata" => Some(Self::SourceTwoMetadata),
            b"post_source_two_preserve" => Some(Self::SourceTwoPreserve),
            b"post_signer_shutdown" => Some(Self::SignerShutdown),
            b"post_host_fence" => Some(Self::HostFence),
            b"post_witness_descriptor" => Some(Self::WitnessDescriptor),
            b"post_handoff_write" => Some(Self::HandoffWrite),
            b"post_external_controls" => Some(Self::ExternalControls),
            b"post_external_bootstrap" => Some(Self::ExternalBootstrap),
            b"post_ready" => Some(Self::Ready),
            _ => None,
        }
    }
}
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) fn post_input_phase(terminal: &crate::terminal::Terminal, phase: PostInputPhase) -> Result<()> {
    terminal.message(&format!("\nSYNTHETIC_COORDINATED_POST_INPUT_PHASE={}\n", phase.label()))
}

/// Retains only a fixed candidate marker and a typed phase, never arbitrary
/// transcript lines. Malformed, repeated, backwards, or partial markers withhold
/// attribution. They do not change workflow result, authority, or cleanup.
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) struct PostInputCapture {
    candidate: zeroize::Zeroizing<[u8; 96]>,
    length: usize,
    ignored: bool,
    invalid: bool,
    latest: Option<PostInputPhase>,
}
impl Default for PostInputCapture {
    fn default() -> Self {
        Self { candidate: zeroize::Zeroizing::new([0; 96]), length: 0,
            ignored: false, invalid: false, latest: None }
    }
}
impl PostInputCapture {
    pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) fn append(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if byte == b'\n' {
                if !self.ignored && self.length != 0 && self.length < POST_INPUT_PREFIX.len() {
                    self.invalid = true;
                } else if !self.ignored && self.length >= POST_INPUT_PREFIX.len() {
                    let mut line = &self.candidate[POST_INPUT_PREFIX.len()..self.length];
                    if line.last() == Some(&b'\r') { line = &line[..line.len()-1]; }
                    match PostInputPhase::parse(line) {
                        Some(phase) if self.latest.is_none_or(|previous| phase > previous) => self.latest = Some(phase),
                        _ => self.invalid = true,
                    }
                }
                self.candidate.fill(0); self.length = 0; self.ignored = false;
            } else if !self.ignored {
                if self.length < POST_INPUT_PREFIX.len() && byte != POST_INPUT_PREFIX[self.length] {
                    self.candidate.fill(0); self.length = 0; self.ignored = true;
                } else if self.length == self.candidate.len() {
                    self.invalid = true; self.candidate.fill(0); self.length = 0; self.ignored = true;
                } else {
                    self.candidate[self.length] = byte; self.length += 1;
                }
            }
        }
    }
    pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification) fn finish(&self) -> Option<PostInputPhase> {
        if self.invalid || (!self.ignored && self.length != 0) { None } else { self.latest }
    }
}

// Container TMPDIR is longer than /tmp. Retain the same private parent and
// random suffix, but leave room for native Unix-domain socket endpoints.
const FULL_ROOT_PREFIX: &str = "f-";
const PASSWORD: &[u8] = b"synthetic-recovery-review-password";
const SOURCE_PASSWORD: &[u8] = b"PUBLIC-NEVER-FUNDED-BORN-ROSTER-QUALIFICATION";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceMetadata {
    version: u16,
    witness: wholepact_authority::WitnessDisclosureDescriptor,
    owner_certificate_digest: String,
    native_entry_correlation: String,
}
fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_HANDOFF { return Err(Error::Invalid); }
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    f.write_all(bytes)?; f.sync_all()?; Ok(())
}
fn done(signers: &worker::JoinedSignerWorkerV1, index: usize) -> Result<()> {
    match signers.receive().map_err(|_| Error::Authentication)? {
        R::Done { index: actual } if actual == index => Ok(()),
        _ => Err(Error::Authentication),
    }
}
fn exact_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn preserve_completed_originals(
    terminal: crate::terminal::Terminal, host: Host,
    mut original: initial::PrivateWorkspaceInitialV1,
    proposal: wholepact_core::ProposalInput, runtime: tokio::runtime::Runtime,
    provider: synthetic_born_provider_v1::SyntheticBornProviderV1,
    profile: PathBuf, workspace: PathBuf, financial: PathBuf,
    disclosures: Vec<OriginalDisclosureV2>,
    fixed_identity: wholepact_protocol::durable_proposal_v1::FixedProposalIdentityV1,
    choices: crate::host::financial::durable_delivery_admission_v2::DeliveryChoicesV2,
    wallet_setup_json: String, live_external_witness: bool,
) -> Result<()> {
    post_input_phase(&terminal, PostInputPhase::InputEntry)?;
    let cutoff = private_fixed_v2::child_original_cutoff()?;
    if disclosures.len() != 2 || wallet_setup_json.is_empty() || Instant::now() >= cutoff {
        return Err(Error::Authentication);
    }
    // Last shared signer TempDir may only be kept after the actual unused
    // anchor and both opened sources have drained, never from caller paths.
    post_input_phase(&terminal, PostInputPhase::AnchorDrain)?;
    original.signers.send(C::DropUnselectedAnchor(0)).map_err(|_| Error::Authentication)?;
    done(&original.signers, 0)?;
    let mut sources = Vec::with_capacity(2);
    let mut preserved_container = false;
    for index in 1..=2 {
        let account = &original.born[index];
        let captured = disclosures.iter().find(|d| d.account_id == account.account_id).ok_or(Error::Authentication)?;
        post_input_phase(&terminal, if index == 1 { PostInputPhase::SourceOneOpen } else { PostInputPhase::SourceTwoOpen })?;
        original.signers.send(C::OpenDelivery(index, proposal.clone())).map_err(|_| Error::Authentication)?;
        match original.signers.receive().map_err(|_| Error::Authentication)? {
            R::DurablePeer { index: actual, .. } if actual == index => (),
            _ => return Err(Error::Authentication),
        }
        post_input_phase(&terminal, if index == 1 { PostInputPhase::SourceOneMetadata } else { PostInputPhase::SourceTwoMetadata })?;
        original.signers.send(C::ReadDeliverySourceMetadata(index)).map_err(|_| Error::Authentication)?;
        let metadata: SourceMetadata = match original.signers.receive().map_err(|_| Error::Authentication)? {
            R::DeliverySourceMetadata { index: actual, json } if actual == index && json.len() <= 16 * 1024 => serde_json::from_str(&json)?,
            _ => return Err(Error::Authentication),
        };
        if metadata.version != 1 || metadata.witness.account_id != account.account_id
            || !exact_hash(&metadata.owner_certificate_digest) || !exact_hash(&metadata.native_entry_correlation) {
            return Err(Error::Authentication);
        }
        metadata.witness.validate().map_err(|_| Error::Authentication)?;
        post_input_phase(&terminal, if index == 1 { PostInputPhase::SourceOnePreserve } else { PostInputPhase::SourceTwoPreserve })?;
        original.signers.send(C::PreserveDelivery(index)).map_err(|_| Error::Authentication)?;
        let selector = match original.signers.receive().map_err(|_| Error::Authentication)? {
            R::DeliveryPreserved { index: actual, original } if actual == index => original,
            _ => return Err(Error::Authentication),
        };
        if selector.account_id != account.account_id || selector.version != 2 { return Err(Error::Authentication); }
        preserved_container |= selector.original_directory_preserved;
        let disclosure_json = serde_json::to_string(&metadata.witness)?;
        let disclosure_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:coordinated-original-financial-disclosure:v1", &metadata.witness,
        ).map_err(|_| Error::Invalid)?;
        sources.push(serde_json::json!({
            "role": if index == 1 { "signer1" } else { "signer2" },
            "reopen_selector": selector,
            "entry_selection": {
                "canonical_root": selector.root, "account_id": account.account_id,
                "original_enrollment_ref": captured.enrollment_ref,
                "original_manifest_ref": captured.accepted_manifest_ref,
                "owner_certificate_digest": metadata.owner_certificate_digest,
                "witness_disclosure_json": disclosure_json,
                "witness_disclosure_digest": disclosure_digest,
                "session_digest": metadata.native_entry_correlation,
                "display": "Actual retained synthetic source before coordinated V3. Historical metadata grants no new native permission.",
                "source_expires_at_ms": original.expiry_ms
            },
            "original_capture": {
                "request": captured.history, "scope": captured.scope,
                "material_digest": captured.material_digest, "outbox_reference": captured.outbox_reference
            }
        }));
    }
    post_input_phase(&terminal, PostInputPhase::SignerShutdown)?;
    original.signers.shutdown().map_err(|_| Error::Authentication)?;
    if !preserved_container || Instant::now() >= cutoff { return Err(Error::Authentication); }
    // Host retains only original files after an explicit fence revocation and
    // drop; no private vault owner remains when the full original root opens.
    post_input_phase(&terminal, PostInputPhase::HostFence)?;
    host.authority.fence.revoke()?;
    drop(host);
    if original.host.is_some() { return Err(Error::Authentication); }
    let account_ids = [original.born[1].account_id.clone(), original.born[2].account_id.clone()];
    post_input_phase(&terminal, PostInputPhase::WitnessDescriptor)?;
    let (witness_bytes, mut live_witness) = if live_external_witness {
        let mut witness = original.witness;
        let bytes = witness.describe_coordinated_pre_v3_originals_v1(&account_ids).map_err(|_|Error::Authentication)?;
        (bytes, Some(witness))
    } else {
        (original.witness.preserve_coordinated_pre_v3_originals_v1(&account_ids).map_err(|_|Error::Authentication)?, None)
    };
    let witness: serde_json::Value = serde_json::from_slice(&witness_bytes)?;
    if witness_bytes.len() > MAX_HANDOFF || witness.get("purpose").and_then(|v| v.as_str()) != Some(if live_external_witness {"coordinated-pre-v3-live-originals-v1"} else {"coordinated-pre-v3-originals-v1"}) {
        return Err(Error::Authentication);
    }
    post_input_phase(&terminal, PostInputPhase::HandoffWrite)?;
    let root = PathBuf::from(std::env::var_os("TMPDIR").ok_or(Error::Invalid)?);
    if !root.is_absolute() || Instant::now() >= cutoff { return Err(Error::Permission); }
    let host_password = root.join("coordinated-fixture-host-password.private");
    let source_password = root.join("coordinated-fixture-source-password.private");
    write_new_private(&host_password, PASSWORD)?;
    write_new_private(&source_password, SOURCE_PASSWORD)?;
    let commands_file = root.join("coordinated-fixture-session-commands.json");
    let choices_file = root.join("coordinated-fixture-delivery-choices.json");
    let wallet_file = root.join("coordinated-fixture-wallet-setup.json");
    write_new_private(&commands_file, &serde_json::to_vec(&serde_json::json!({
        "version": 1, "bind_key": "synthetic-coordinated-bind-v1",
        "intake_keys": ["synthetic-coordinated-intake-one-v1", "synthetic-coordinated-intake-two-v1"],
        "completion_key": "synthetic-coordinated-complete-v1"
    }))?)?;
    write_new_private(&choices_file, &serde_json::to_vec(&choices)?)?;
    write_new_private(&wallet_file, wallet_setup_json.as_bytes())?;
    for (index, source) in sources.iter_mut().enumerate() {
        let entry_file = root.join(format!("coordinated-fixture-source-{}-entry.json", index + 1));
        let continuation_output = root.join(format!("coordinated-source-{}-continuation.json", index + 1));
        let result_output = root.join(format!("coordinated-source-{}-result.json", index + 1));
        if continuation_output.exists() || result_output.exists() { return Err(Error::Authentication); }
        write_new_private(&entry_file, &serde_json::to_vec(&source["entry_selection"])?)?;
        source["entry_selection_file"] = serde_json::to_value(entry_file)?;
        // Destinations only. Only the actual C native Save action creates them.
        source["continuation_output_file"] = serde_json::to_value(continuation_output)?;
        source["result_output_file"] = serde_json::to_value(result_output)?;
    }
    let wall_ms: u64 = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Invalid)?.as_millis().try_into().map_err(|_| Error::Invalid)?;
    let remaining_ms: u64 = cutoff.checked_duration_since(Instant::now()).ok_or(Error::Permission)?
        .as_millis().try_into().map_err(|_| Error::Invalid)?;
    let fixture_expires_at_ms = original.expiry_ms.min(wall_ms.checked_add(remaining_ms).ok_or(Error::Invalid)?);
    let control = serde_json::json!({
        "version": 1, "purpose": if live_external_witness {"genuine-coordinated-financial-live-pre-v3-v1"} else {"genuine-coordinated-financial-pre-v3-v1"},
        "profile": profile, "workspace": workspace, "financial": financial,
        "fixed_identity": fixed_identity, "delivery_choices": choices,
        "sources": sources, "witness": witness,
        "wallet_setup_json": wallet_setup_json,
        "session_commands_file": commands_file, "delivery_choices_file": choices_file,
        "wallet_setup_file": wallet_file,
        "host_password_file": host_password, "source_password_file": source_password,
        "original_fixture_expires_at_ms": fixture_expires_at_ms,
        "prepared_v3": false, "admitted_v3": false, "signed": false,
        "dispatch_requested": false, "full_product_verified": false
    });
    let encoded = serde_json::to_vec(&control)?;
    write_new_private(&root.join(READY_FILE), &encoded)?;
    if let Some(witness) = live_witness.as_mut() {
        super::coordinated_external_witness_v1::run(&terminal, witness, &account_ids, &root, cutoff, original.expiry_ms)?;
    } else {
        post_input_phase(&terminal, PostInputPhase::Ready)?;
        terminal.message("SYNTHETIC_COORDINATED_PRE_V3_ORIGINALS_READY=1\n")?;
    }
    // Keep the same actual Host TempDir and live finite mock provider. This is
    // a fixture-owner wait, not permission for the consumer or a new lifetime.
    let _original_host_directory = original.temporary;
    while Instant::now() < cutoff { std::thread::sleep(std::time::Duration::from_millis(20)); }
    runtime.block_on(provider.shutdown())?;
    Err(Error::Permission)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_requires_original_hash_shape() {
        assert!(!exact_hash("")); assert!(!exact_hash(&"g".repeat(64)));
        assert!(exact_hash(&"a".repeat(64)));
    }
    #[test]
    fn source_metadata_is_closed() {
        assert!(serde_json::from_str::<SourceMetadata>(r#"{"version":1,"restored_grant":true}"#).is_err());
    }
}

const READY_MARKER: &str = "SYNTHETIC_COORDINATED_PRE_V3_ORIGINALS_READY=1";
const PUBLIC_READY_LINE: &str = "\nCI_FINANCIAL_FIXTURE_READY version=1";
const PARENT_READY: &str = "coordinated-financial-ready-v1.json";
const ORIGINAL_LIMIT: std::time::Duration = std::time::Duration::from_secs(900);

pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification)
fn ready_marker(tail: &str, inputs_complete: bool, terminal: bool) -> std::io::Result<bool> {
    let count = tail.split_inclusive('\n').filter(|line| line.ends_with('\n'))
        .map(|line| line.trim_end_matches('\n').trim_end_matches('\r'))
        .filter(|line| *line == READY_MARKER).count();
    if count > 1 || (count == 1 && !inputs_complete) {
        return Err(std::io::Error::other("premature or duplicate full fixture marker"));
    }
    if terminal {
        let remainder = tail.rsplit_once('\n').map_or(tail, |(_, rest)| rest);
        if count != 1 || (!remainder.is_empty() &&
            (READY_MARKER.starts_with(remainder) || remainder.starts_with(READY_MARKER))) {
            return Err(std::io::Error::other("full fixture terminal marker refused"));
        }
    }
    Ok(count == 1)
}

fn monotonic_ns() -> std::io::Result<u64> {
    let mut raw = std::mem::MaybeUninit::<libc::timespec>::zeroed();
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, raw.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let raw = unsafe { raw.assume_init() };
    let secs = u64::try_from(raw.tv_sec).map_err(|_| std::io::Error::other("monotonic clock refused"))?;
    let nanos = u64::try_from(raw.tv_nsec).map_err(|_| std::io::Error::other("monotonic clock refused"))?;
    if nanos >= 1_000_000_000 { return Err(std::io::Error::other("monotonic clock refused")); }
    secs.checked_mul(1_000_000_000).and_then(|n| n.checked_add(nanos))
        .ok_or_else(|| std::io::Error::other("monotonic clock refused"))
}

fn parent_directory() -> std::io::Result<(PathBuf, std::fs::File)> {
    use std::os::unix::fs::MetadataExt;
    let path = PathBuf::from(std::env::var_os("TMPDIR").ok_or_else(|| std::io::Error::other("full fixture parent root missing"))?);
    if !path.is_absolute() { return Err(std::io::Error::other("full fixture parent root refused")); }
    let file = OpenOptions::new().read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&path)?;
    let meta = file.metadata()?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o777 != 0o700 {
        return Err(std::io::Error::other("full fixture parent root refused"));
    }
    Ok((path, file))
}

/// Retain the actual child/provider only after its exact preparation inputs and
/// complete ready line. No private PTY bytes, paths, passwords or lengths leave
/// this parent. FINISH is fixture cleanup, never product success evidence.
pub(in crate::host::manual_enrollment::command::roster_publication_v2::sequential_construction_v3::qualification)
fn hold_ready_fixture(
    child: &mut owned_test_process_group_v1::OwnedTestProcessGroupV1,
    deadline: Instant, original_monotonic_cutoff_ns: u64,
) -> std::io::Result<()> {
    use std::io::Write;
    if Instant::now() >= deadline || child.observe_exit()?.is_some() {
        return Err(std::io::Error::other("full fixture owner no longer live"));
    }
    let (parent, parent_handle) = parent_directory()?;
    let fixture_path = child.temporary_root().join(READY_FILE);
    let descriptor = crate::files::read_private(&fixture_path, MAX_HANDOFF)
        .map_err(|_| std::io::Error::other("full fixture descriptor refused"))?;
    let value: serde_json::Value = serde_json::from_slice(&descriptor)
        .map_err(|_| std::io::Error::other("full fixture descriptor refused"))?;
    if !matches!(value.get("purpose").and_then(|v|v.as_str()), Some("genuine-coordinated-financial-pre-v3-v1" | "genuine-coordinated-financial-live-pre-v3-v1"))
        || ["prepared_v3","admitted_v3","signed","dispatch_requested","full_product_verified"].iter()
            .any(|k| value.get(k).and_then(|v|v.as_bool()) != Some(false)) {
        return Err(std::io::Error::other("full fixture descriptor refused"));
    }
    let ready = serde_json::to_vec(&serde_json::json!({
        "version":1, "fixture_path":fixture_path,
        "original_monotonic_cutoff_ns":original_monotonic_cutoff_ns,
    })).map_err(|_| std::io::Error::other("full fixture ready encoding refused"))?;
    write_new_private(&parent.join(PARENT_READY), &ready)
        .map_err(|_| std::io::Error::other("full fixture ready publication refused"))?;
    parent_handle.sync_all()?;
    println!("{PUBLIC_READY_LINE}");
    std::io::stdout().flush()?;
    let mut line = Vec::with_capacity(7);
    loop {
        if Instant::now() >= deadline || monotonic_ns()? >= original_monotonic_cutoff_ns {
            return Err(std::io::Error::other("full fixture original cutoff expired"));
        }
        if child.observe_exit()?.is_some() { return Err(std::io::Error::other("full fixture owner exited")); }
        let mut descriptor = libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 };
        let polled = unsafe { libc::poll(&mut descriptor, 1, 20) };
        if polled < 0 { return Err(std::io::Error::last_os_error()); }
        if descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(std::io::Error::other("full fixture control failed"));
        }
        if descriptor.revents & (libc::POLLIN | libc::POLLHUP) == 0 { continue; }
        let mut byte = 0u8;
        let n = unsafe { libc::read(0, (&mut byte as *mut u8).cast(), 1) };
        if n != 1 { return Err(std::io::Error::other("full fixture control ended")); }
        line.push(byte);
        if line.len() > 7 { return Err(std::io::Error::other("full fixture control refused")); }
        if byte == b'\n' {
            if !matches!(line.as_slice(), b"FINISH\n" | b"CANCEL\n") {
                return Err(std::io::Error::other("full fixture control refused"));
            }
            if Instant::now() >= deadline || child.observe_exit()?.is_some() {
                return Err(std::io::Error::other("full fixture owner ended before cleanup"));
            }
            return Ok(());
        }
    }
}

fn full_fixture_inputs() -> Vec<Input<'static>> {
    let mut inputs = private_fixed_v2::producer_inputs();
    inputs.pop(); // Remove only the old post-fixed process-death prompt.
    for detail in [
        "Read exact current selected original source and complete historical terms for NONSPENDING private coordination.",
        "Open ONLY the exact initialized original private workspace.",
        "Inspect exact original private V3 stage metadata.",
        "Approve V3 private fixed stage ReadFixed.",
        "Store this exact new dispatcher credential only",
        "Inspect all original source/workspace/proof/financial/submission identities",
        "Authenticate the same final-v4 original workspace",
    ] { inputs.push(Input::ExactReview { detail, approve: true }); }
    private_fixed_v2::session_inputs(&mut inputs, false);
    inputs.push(Input::ExactReview {
        detail: "Inspect original fixed-prefix and bounded admission-export history metadata", approve: true,
    });
    inputs
}

#[test]
#[ignore = "Approved isolated disposable full-flow fixture parent only; retains actual mock provider until FINISH/CANCEL and verified fixture cleanup"]
fn coordinator_full_financial_fixture_parent() { run_full_fixture_parent(false); }

#[test]
#[ignore = "Approved isolated disposable live original Witness operator fixture only"]
fn coordinator_live_full_financial_fixture_parent() { run_full_fixture_parent(true); }

// Only compile-time phase/reason tokens and bounded input counters leave this
// parent. Never serialize an io::Error, transcript, challenge, or source record.
fn run_full_fixture_parent(live_external_witness: bool) {
    let mut phase = "core_policy";
    let mut reason = String::from("Setup");
    let mut next = 0usize;
    let mut expected = 0usize;
    let mut process_cleanup = false;
    let mut root_cleanup = false;
    let result = (|| -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        process_containment_v1::require_and_report_core_policy()?;
        phase = "wait_policy";
        owned_test_process_group_v1::require_default_child_wait_policy()?;
        // One cutoff precedes ALL source, TLS, birth, proof and native setup.
        phase = "cutoff";
        let started = Instant::now();
        let cutoff_ns = monotonic_ns()?.checked_add(900_000_000_000)
            .ok_or_else(|| std::io::Error::other("full fixture cutoff overflow"))?;
        let deadline = started.checked_add(ORIGINAL_LIMIT)
            .ok_or_else(|| std::io::Error::other("full fixture cutoff overflow"))?;
        phase = "parent_directory";
        let (base, base_handle) = parent_directory()?;
        phase = "temporary_root";
        let root = owned_test_process_group_v1::PreSpawnTemporaryRootV1::new(
            tempfile::Builder::new().prefix(FULL_ROOT_PREFIX)
                .permissions(std::fs::Permissions::from_mode(0o700)).tempdir_in(&base)?,
        );
        phase = "tls_material";
        let tls = synthetic_provider_tls_v1::ChildTlsMaterialV1::prepare(root.path())?;
        let inputs = full_fixture_inputs();
        phase = "child_stage";
        expected = inputs.len();
        let mut stage = private_workspace_stage_v1(
            root.into_tempdir(), Some(&tls), if live_external_witness {PrivateWorkspaceStageV1::CoordinatedLiveFixture} else {PrivateWorkspaceStageV1::CoordinatedFixture},
            &inputs, deadline, cutoff_ns,
        )?;
        drop(tls);
        next = stage.next;
        expected = stage.expected;
        reason = format!("{:?}", stage.failure_reason);
        phase = "cleanup";
        let cleanup_verified = stage.process.verified();
        let root_removed = if let Some(root) = stage.root.take() {
            matches!(close_owned_temporary_root(root), TemporaryRootCleanupV1::ClosedAndAbsenceVerified)
        } else { false };
        process_cleanup = cleanup_verified;
        root_cleanup = root_removed;
        if !cleanup_verified || !root_removed || stage.child_pid == 0 { reason = "CleanupUnverified".into(); return Err(std::io::Error::other("full fixture cleanup unverified")); }
        phase = "cleanup_record";
        // The caller owns the parent directory and its inert ready pointer.
        // Do not remove an artifact if publication failed before ownership was
        // established. Its pointed-to actual child root is proven absent here.
        base_handle.sync_all()?;
        use std::os::unix::process::ExitStatusExt;
        let status = stage.process.status.as_ref().ok_or_else(||std::io::Error::other("fixture wait status missing"))?;
        let cleanup = serde_json::to_vec(&serde_json::json!({
            "version":1,"actual_child_pid":stage.child_pid,
            "actual_wait_status":{"exit_code":status.code(),"signal":status.signal()},
            "owned_group_absent":true,"root_absent":true,
        })).map_err(|_|std::io::Error::other("fixture cleanup encoding refused"))?;
        write_new_private(&base.join("coordinated-financial-cleanup-v1.json"), &cleanup)
            .map_err(|_|std::io::Error::other("fixture cleanup evidence refused"))?;
        base_handle.sync_all()?;
        phase = "completion";
        if stage.outcome.is_err() || stage.next != stage.expected || Instant::now() >= deadline {
            if stage.outcome.is_err() || stage.next != stage.expected {
                phase = stage.coordinated_post_input_phase.map_or("child_stage", PostInputPhase::label);
            }
            else { reason = "Deadline".into(); }
            return Err(std::io::Error::other("full fixture preparation or original lifetime failed"));
        }
        println!("CI_FINANCIAL_FIXTURE_CLEANED version=1");
        std::io::stdout().flush()?;
        Ok(())
    })();
    if result.is_err() {
        // A leading newline separates this marker from libtest's progress text.
        println!("\nCI_FINANCIAL_FIXTURE_DIAGNOSTIC {}", serde_json::json!({
            "version": 1, "phase": phase, "reason": reason,
            "next": next, "expected": expected,
            "process_cleanup": process_cleanup, "root_cleanup": root_cleanup,
        }));
        let _ = std::io::stdout().flush();
    }
    assert!(result.is_ok(), "genuine full fixture parent failed");
}

#[test]
fn full_fixture_marker_requires_complete_inputs_and_one_complete_line() {
    assert!(!ready_marker(READY_MARKER, true, false).unwrap());
    let line = format!("{READY_MARKER}\n");
    assert!(ready_marker(&line, true, false).unwrap());
    assert!(ready_marker(&line, false, false).is_err());
    assert!(ready_marker(&(line.clone()+&line), true, true).is_err());
}

#[test]
fn full_fixture_container_layout_fits_native_unix_socket_paths() {
    use std::os::unix::ffi::OsStrExt;
    let candidate = |outer: &str, inner: &str| {
        Path::new("/ci-fixture/full-parent")
            .join(format!("{outer}aaaaaa"))
            .join(format!("{inner}bbbbbb"))
            .join(format!("requests-{}.sock", hex::encode([0u8; 12])))
    };
    // Reproduce the exact prior layout; Linux sockaddr_un has 108 bytes,
    // including the terminating NUL. This was not covered by /tmp-only tests.
    assert_eq!(candidate("full-original-", "wholepact-born-manual-ipc-")
        .as_os_str().as_bytes().len(), 116);
    for inner in ["wholepact-born-manual-ipc-", "wholepact-born-stop-", ".tmp"] {
        assert!(candidate(FULL_ROOT_PREFIX, inner).as_os_str().as_bytes().len() < 108);
    }
    assert!(full_fixture_inputs().len() <= 4096);
}

#[test]
fn full_fixture_container_layout_bind_rejects_old_and_accepts_short_private_root() {
    use std::os::unix::{fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        ffi::OsStrExt, net::UnixListener};
    // Same byte length as the actual container base, without needing to create
    // or weaken /ci-fixture locally. All directories are owned fresh and 0700.
    let base = tempfile::Builder::new().prefix("wp-ci-binds-")
        .permissions(std::fs::Permissions::from_mode(0o700)).tempdir_in("/tmp").unwrap();
    assert_eq!(base.path().as_os_str().as_bytes().len(),
        Path::new("/ci-fixture/full-parent").as_os_str().as_bytes().len());
    for (prefix, should_bind) in [("full-original-", false), (FULL_ROOT_PREFIX, true)] {
        let endpoint = base.path().join(format!("{prefix}aaaaaa"))
            .join("wholepact-born-manual-ipc-bbbbbb");
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&endpoint).unwrap();
        for directory in [endpoint.as_path(), endpoint.parent().unwrap(), base.path()] {
            let metadata = std::fs::symlink_metadata(directory).unwrap();
            assert!(metadata.is_dir());
            assert_eq!(metadata.mode() & 0o777, 0o700);
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        }
        let socket = endpoint.join(format!("requests-{}.sock", hex::encode([0u8; 12])));
        let result = UnixListener::bind(&socket);
        if should_bind {
            let listener = result.expect("short private fixture layout must support native pathname sockets");
            assert_eq!(listener.local_addr().unwrap().as_pathname(), Some(socket.as_path()));
            assert_eq!(std::fs::symlink_metadata(&socket).unwrap().uid(), unsafe { libc::geteuid() });
            drop(listener);
        } else {
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
        }
    }
}

#[test]
fn full_fixture_public_ready_line_is_separate_from_libtest_progress() {
    let emitted = format!("test fixture ... {PUBLIC_READY_LINE}\n");
    assert_eq!(emitted.lines().last(), Some("CI_FINANCIAL_FIXTURE_READY version=1"));
    assert_eq!(emitted.lines().count(), 2);
}

#[test]
fn full_fixture_post_input_capture_handles_every_split_and_terminal_drain() {
    let bytes = b"private output ignored\nSYNTHETIC_COORDINATED_POST_INPUT_PHASE=post_final_inspection\r\nSYNTHETIC_COORDINATED_POST_INPUT_PHASE=post_input_entry\nSYNTHETIC_COORDINATED_POST_INPUT_PHASE=post_witness_descriptor\n";
    for split in 0..=bytes.len() {
        let mut capture = PostInputCapture::default();
        capture.append(&bytes[..split]);
        // The same append method is used by the final, verified post-reap drain.
        capture.append(&bytes[split..]);
        assert_eq!(capture.finish(), Some(PostInputPhase::WitnessDescriptor));
    }
}

#[test]
fn full_fixture_post_input_capture_withholds_malformed_or_unordered_markers() {
    let first = b"SYNTHETIC_COORDINATED_POST_INPUT_PHASE=post_input_entry\n";
    for tail in [
        b"SYNTHETIC_COORDINATED_POST_INPUT_PHASE=private-value\n".as_slice(),
        b"SYNTHETIC_COORDINATED_POST_INPUT_PHASE=post_input_entry\n".as_slice(),
        b"SYNTHETIC_COORDINATED_POST_INPUT_PHASE=post_final_inspection\n".as_slice(),
        b"SYNTHETIC_COORDINATED_POST_INPUT_PHASE=post_witness_descriptor".as_slice(),
        b"SYNTHETIC_COORDINATED_POST_\n".as_slice(),
    ] {
        let mut capture = PostInputCapture::default();
        capture.append(first); capture.append(tail);
        assert_eq!(capture.finish(), None);
    }
    let mut capture = PostInputCapture::default();
    capture.append(first); capture.append(POST_INPUT_PREFIX); capture.append(&[b'x'; 4096]);
    capture.append(b"\nSYNTHETIC_COORDINATED_POST_INPUT_PHASE=post_ready\n");
    assert_eq!(capture.finish(), None);
    assert_eq!(capture.candidate.len(), 96);
}
